---
tempo: patch
---

Fix `is_hardfork_active` returning `false` for every fork when the node is already on a hardfork this SDK does not know. It now reads the requested fork's own flag from the `tempo_forkSchedule` schedule in that case, so an older release still answers correctly after a network upgrade.
