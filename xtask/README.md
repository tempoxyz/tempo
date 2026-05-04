# tempo-xtask

A polyfill to perform various operations on the codebase.

Subcommands (see `cargo x --help`):

- `generate-genesis`: write genesis JSON (and optional validator artifacts) for local testing.
- `generate-localnet`: generate a multi-validator local layout (genesis, keys, suggested `tempo` commands).
- `generate-devnet`: generate devnet-style configs (Docker image tag + genesis URL).
- `generate-add-peer`: add a peer to an existing network (addresses + signing material).
- `generate-state-bloat`: emit a TIP-20 state-bloat binary for genesis loading.
- `get-dkg-outcome`: dump DKG outcome from a block's `extra_data` via RPC.
