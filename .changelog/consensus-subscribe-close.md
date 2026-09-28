---
tempo: patch
---

Stop `consensus_subscribe` tasks as soon as the client disconnects or unsubscribes instead of waiting for the next finalization to fail a send. Previously, a stalled chain let disconnected subscriptions accumulate and kept per-connection subscription permits held after `consensus_unsubscribe`.
