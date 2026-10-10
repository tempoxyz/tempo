# tempo-xtask

Zones tooling is available through `cargo zone-xtask` (the `tempo-zone-xtask`
binary). See the [Zones command reference](../zones/xtask/README.md).


A polyfill to perform various operations on the codebase.

Subcommands currently supported:

+ `generate-config`: generates a set of validators to run a local network.
+ `add-hardfork --hardfork T11`: generates the mechanical plumbing for a new hardfork and rotates
  the `default`/`next` Foundry profiles.
