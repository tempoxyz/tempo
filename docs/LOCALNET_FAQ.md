# Localnet FAQ

A small collection of frequently asked questions about running Tempo
locally.

## The localnet does not start

- Make sure `just` is installed.
- Run `just` without arguments to see available recipes.
- Check that no other process is using the same ports (see `scripts/check_localnet_ports.sh` if available).

## I cannot connect via RPC

- Confirm the RPC URL is correct (for example `http://127.0.0.1:8545`).
- Use `curl` with a simple `eth_blockNumber` request to verify connectivity.
- Check container or process logs for errors.

## How do I reset my local chain?

- Stop the localnet.
- Remove the data directory used by Tempo (see the documentation for the exact path).
- Start the localnet again.

This FAQ is intentionally short and meant to complement the main
documentation in the README.
