# Local services in Amp orbs

The repository's `.agents/setup` installs the tools, prepares a pinned checkout of
Tempo Explorer, and caches the TIDX and database images. Application
processes belong to `.amp/services.yaml`; setup and resume do not start them.
Setup also generates L1 genesis from the locked Tempo dependency and the zone
contract artifacts, including the native ZoneFactory owned by the dev account.

From the repository root in an orb:

```sh
amp orb services ensure
node .amp/smoke.mjs
```

Open the URLs printed by `ensure` or use the Portal tab:

- **Local zone explorer**: Tempo Explorer, using the zone's generated chain ID.
- **Local TIDX**: indexer status; `/query` accepts SQL queries.
- **Local zone devnet**: operator JSON-RPC endpoint (use POST).
- **Local Tempo L1**: Anvil in Tempo mode, anchoring the zone locally.

PostgreSQL, ClickHouse, and the Tempo API run as internal services. The API uses
the same locked package as the explorer's client. Explorer browser RPC requests
go through its own `/api/rpc` proxy; server-side requests use loopback backends.
This avoids cross-portal CORS/authentication problems. No shared chain RPC or
indexer credentials are required.

## State and restarts

All generated state lives under ignored `.amp/state/`: Anvil state, zone genesis
and node data, and database files. The zone is provisioned once with the standard
Anvil development account; subsequent starts run `tempo-zone node` because
`tempo-zone dev` would erase the existing node data. The operator RPC exposes
development accounts and unredacted data; keep these portals restricted to the
thread's viewers.

Use `amp orb service logs <name>` for failures and `amp orb service restart <name>`
after changing service code. Anvil periodically saves its state; a hard stop can
lose the most recent second. Do not replace/reset L1 state independently of the
zone and indexer databases. To intentionally start a completely fresh stack,
stop all services and move `.amp/state/` aside together before ensuring services
again. Keep the old directory if its data is needed.

Fixed loopback ports are declared in `services.yaml` and used by the service
scripts: L1 8545, zone 9545 (WS 9546, P2P 9547, redacted RPC 8544), PostgreSQL
15432, ClickHouse 18123/19000, TIDX 18080, Tempo API 18787, explorer 13000.
Update both the manifest and scripts when changing these ports.

## Dependency updates

Pins live in `versions.env`. The explorer adapter uses a Vite plugin scoped to
that checkout; it does not edit its source files. When updating the explorer,
review the adapter's module paths and rerun the smoke check and browser checks.
Setup refuses to silently replace an existing checkout at a different revision.
The pinned TIDX image requires an x86_64 orb and includes its own glibc runtime.

After changing setup, delete the project's cached snapshot in Amp project
settings so a fresh orb runs it. Changing setup alone does not invalidate a
matching snapshot. See [Amp customization](https://ampcode.com/docs/orbs/customizing)
and [portal documentation](https://ampcode.com/docs/orbs/portals).

Local HTTP checks do not verify Amp portal routing or viewer authentication.
After ensuring services in an orb, also open the exact generated explorer URL,
check that blocks appear, and open the TIDX status portal.
