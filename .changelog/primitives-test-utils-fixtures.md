---
tempo-primitives: minor
---

Added `tempo_primitives::test_utils` behind the `test-utils` feature: `actors`, `actors_vec` and `amounts`, drawn from a per-thread test RNG seeded from `TEMPO_TEST_SEED` (or randomly, printing the seed on panic so failures replay).
