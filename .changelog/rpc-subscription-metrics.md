---
tempo: patch
---

Track active JSON-RPC subscriptions in metrics (`reth_rpc_server_subscriptions_*`): open, closed, active and rejected counts per transport, the largest active count on any connection, the per-connection peak at close, and per-method/kind open and active counts. Covers `eth_subscribe`, `reth_subscribe*`, `debug_subscribe` and `consensus_subscribe`.
