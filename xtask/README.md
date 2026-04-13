# tempo-xtask

A polyfill to perform various operations on the codebase.

Subcommands (see `cargo xtask --help`):

- `generate-genesis` — write `genesis.json` (and optional validator artifacts) under `--output`
- `generate-localnet` — genesis plus per-validator dirs and keys for a local multi-validator setup
- `generate-devnet` — devnet-style layout (see `--help`)
- `generate-add-peer` — emit config for adding a peer to an existing network
- `generate-state-bloat` — produce a TIP-20 state bloat binary for testing
- `get-dkg-outcome` — read DKG outcome from an RPC block / epoch
