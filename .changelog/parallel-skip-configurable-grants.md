---
tempo-payload-builder: patch
---

The parallel builder no longer replays transactions whose inline key authorization grants a configurable account, since replay does not track the grant target's code.
