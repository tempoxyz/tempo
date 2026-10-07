# tempo-xtask

A polyfill to perform various operations on the codebase.

Subcommands currently supported:

+ `generate-config`: generates a set of validators to run a local network.
+ `add-hardfork --hardfork T11`: generates the mechanical plumbing for a new hardfork and rotates
  the `default`/`next` Foundry profiles.

Zones administration and development tools are available under `cargo xtask zones`.
Use `cargo xtask zones --help` to list commands and
`cargo xtask zones admin --help` for the administration command group. For example:

```sh
cargo xtask zones generate-p2p-key --out p2p.key
cargo xtask zones generate-zone-genesis --help
cargo xtask zones check-abi
```

Zones contract artifacts default to `crates/zones/contracts/out` (benchmark fixtures
use `crates/zones/contracts/benchmark-out`). Run these commands from the repository
root, or supply an explicit artifacts path where supported. The existing
`cargo xtask check-abi` command continues to check Tempo's contracts.
