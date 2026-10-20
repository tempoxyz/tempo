---
tempo-chainspec: major
tempo-hardfork: major
---

Scheduled T13 activation on Moderato for 29 October 2026 at 15:00 UTC and mainnet for 3 November 2026 at 15:00 UTC. Updated public hardfork timestamp lookups to return the scheduled times. Public-network Zones must update an explicit `null` in `config.t13Time` to the parent activation timestamp before restarting; startup rejects disabled parent forks to prevent settlement from using the old ABI after L1 upgrades.
