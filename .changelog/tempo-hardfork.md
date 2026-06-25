---
"tempo-hardfork": minor
"tempo-contracts": minor
"tempo-primitives": minor
"tempo-chainspec": minor
"tempo-alloy": minor
---

Extracts Tempo hardfork definitions and activation schedules into a new `tempo-hardfork` crate for SDK reuse without chainspec dependencies.

Updates `tempo-alloy` to depend on and re-export `tempo-hardfork` instead of `tempo-chainspec`.
