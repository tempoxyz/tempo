---
tempo-alloy: patch
---

Added sponsored transaction support via a new `RelayTransport` that routes `eth_sendRawTransaction` requests through a sponsor service.
Introduced `SponsorFiller`, `SponsoredProviderBuilder`, and `.sponsor()` / `.sponsor_with_config()` provider builder extensions supporting both sign-and-relay and sign-only modes.
