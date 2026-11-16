---
zone-evm: minor
zone-l1: patch
zone-node: patch
zone-precompiles: minor
---

From T15, Zones read the TIP-1022 address registry from finalized Tempo state, so transfers and deposits to a registered virtual address credit its master, and withdrawals reject a virtual fallback recipient. Sequencer allowlists never list a virtual address, so a listed virtual address can't pass funds to its unlisted master.
