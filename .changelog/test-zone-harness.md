---
---

Reworked the zone test harness: `ZoneTestNode::launch(ZoneLaunch { .. })` and `start_real_p2p_cluster(ClusterConfig { .. })` replace the per-knob constructor variants. `Network::builder().zone(..).accounts(n, fund).start()` brings up a dev L1 with zones and funded accounts, whose `deposit` and `withdraw` wait for the resulting balance, as does `L1Fixture::deposit`. The hardfork tests' T13 offsets and the handoff tests' quiescence window are shortened, and in-test timeouts stay under nextest's 3-minute kill. Added `L1Fixture::fork_of` and a test that a zone rejects a fork of L1 history it already consumed. Test-only change.
