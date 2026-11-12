---
tempo-alloy: patch
---

`SponsorFiller` marks a request before the other fillers prepare, and `TempoGasFiller` estimates a sponsored request without its fees, so an unfunded sender no longer fails gas estimation when it sets `max_fee_per_gas`.

Because the marker is now set in `fill_sync`, every filler's `prepare` sees `FEE_PAYER_SIGNATURE_MARKER` on a sponsored request:

- A custom filler that sends the request to a node in `prepare` (such as `eth_call` or `eth_estimateGas`) now sends the marker, which nodes before T14 reject. Strip it in that filler, as `TempoGasFiller` does.
- A sponsored request is treated as a Tempo AA request from the start, so `TempoGasFiller` waits for `chain_id` and `from`, and refuses a legacy `gas_price` in `prepare` with `LegacyGasPriceUnsupported` instead of later.
