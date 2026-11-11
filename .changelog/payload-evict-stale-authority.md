---
tempo-evm: minor
tempo-payload-builder: patch
---

Added `TempoInvalidTransaction::is_stale_authority`. The payload builder now removes a pool transaction from the pool when it fails execution with a stale-authority or bad-transaction error, instead of only skipping it for the current build.
