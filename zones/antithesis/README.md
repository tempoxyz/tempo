# Zone test environment

A multi-sequencer zone in Docker Compose, for fault-injection testing of the zone node built with
`--features fuzz` (SDK assertions enabled). `docker-compose.yaml` describes the topology.

Build the images from the repository root, with the contract submodules checked out:

```bash
docker build -f zones/antithesis/Dockerfile -t tempo-zones-antithesis:latest \
    --build-arg VERGEN_GIT_SHA="$(git rev-parse HEAD)" .
docker build -f zones/antithesis/Dockerfile.config -t tempo-zones-antithesis-config:latest zones/antithesis
```

Run it locally:

```bash
docker compose -f zones/antithesis/docker-compose.yaml up
```

`ZONES_IMAGE` overrides the image the services run.

## Test commands

`test/` holds the Antithesis test commands, installed in the image at
`/opt/antithesis/test/v1/zones` and run in the `workload` container:

- `parallel_driver_fresh_account_journeys.sh` runs [txgen](https://github.com/tempoxyz/txgen)
  journeys (`txgen/journey.yml`) against a random zone node. Each journey deposits pathUSD from L1
  to two accounts the zone has never seen, then one of them withdraws to a new L1 address, so the
  zone and L1 state keep growing. Journeys may fail from faults (timeouts, RPC errors); any other
  failure, such as a reverted transaction, fails an `Always` assertion.
- `eventually_portal_backing.sh` checks, once faults stop, that the portal's escrow backs the zone's
  supply plus pending deposits, withdrawals and refunds (`tempo-zone-xtask verify-portal-backing`).

Run one against the local stack:

```bash
docker compose -f zones/antithesis/docker-compose.yaml exec workload \
    /opt/antithesis/test/v1/zones/parallel_driver_fresh_account_journeys.sh
```
