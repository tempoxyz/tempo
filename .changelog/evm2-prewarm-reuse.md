---
tempo-evm: minor
---

Let engine validation commit transaction results from prewarming when their reads still match, enabled with `--engine.prewarm-reuse`. System, subblock and expiring nonce transactions, and transactions whose payment lane depends on the hardfork, still execute normally.
