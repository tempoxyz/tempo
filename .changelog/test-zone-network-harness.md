---
---

Added `Network::builder().zone(..).accounts(n, fund).start()`, which brings up a dev L1 with zones and funded accounts, and `L1Fixture::deposit`. `Zone::deposit` and `Zone::withdraw` wait for the resulting balance, replacing the deposit-then-poll sequences in the zone tests. Test-only change.
