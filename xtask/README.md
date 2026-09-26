# tempo-xtask

A polyfill to perform various operations on the codebase.

Subcommands currently supported:

+ `generate-config`: generates a set of validators to run a local network.
+ `add-hardfork --hardfork T11`: generates the mechanical plumbing for a new hardfork and rotates
  the `default`/`next` Foundry profiles.

New forks added by `add-hardfork` are disabled by default in the `generate-genesis` and
`generate-localnet` commands. Pass `--tN-time <unix-timestamp>` to schedule one, or
`--tN-time 0` to explicitly enable it at genesis. Existing fork defaults are preserved.
The built-in `--chain dev` chainspec and test fixtures enable every known fork at genesis;
use an explicitly scheduled genesis file for a persistent network.

For a persistent devnet, roll out support to every validator before the activation timestamp.
Adding a fork or rolling out feature code must not implicitly activate it on that network.
Do not remove or move activation timestamps for forks the network has already used.
