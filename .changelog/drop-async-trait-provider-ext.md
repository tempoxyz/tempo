---
tempo-alloy: minor
---

`TempoProviderExt` methods no longer use `async_trait`: they return an opaque `impl Future` (`Send` on native targets) instead of `Pin<Box<dyn Future>>`. The returned futures are not `Unpin`, so callers that store, `select` or `poll_unpin` them must `Box::pin` them first.
