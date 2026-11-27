---
tempo-consensus: patch
---

The follower's upstream websocket client accepts messages and frames up to 8x the maximum RLP block size, so a full block sent as JSON no longer exceeds the 16 MiB default frame limit and drops the connection.
