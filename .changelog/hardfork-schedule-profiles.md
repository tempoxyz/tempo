---
tempo-hardfork: minor
tempo-chainspec: minor
---

Add `TempoHardfork::genesis_key`, derive `TempoGenesisInfo` fork fields from the hardfork list, and add reusable `--hardfork`/`--<fork>-time` genesis generator arguments (`tempo_chainspec::cli::TempoHardforkArgs`).
