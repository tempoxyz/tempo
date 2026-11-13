---
---

Shortened the zone handoff tests' quiescence window to 1s on the in-memory L1, set the T13 activation offsets of the zone hardfork tests from their measured setup time (15s to 6s, 30s to 20s), and kept in-test timeouts under nextest's 3-minute kill. Test-only change.
