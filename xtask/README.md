# tempo-xtask

A polyfill to perform various operations on the codebase.

Subcommands currently supported:

+ `generate-config`: generates a set of validators to run a local network.
+ `add-hardfork --hardfork T11`: generates the mechanical plumbing for a new hardfork and rotates
  the `default`/`next` Foundry profiles.
+ `get-verifier-pcrs --chain moderato`: queries the RPC for the newest successful Nitro
  batch verification in the active hardfork and prints PCR0/1/2 as JSON, alongside the
  transaction, block, portal and verifier that accepted them. Use `--rpc-url` to override the
  endpoint, `--hardfork T13` to select a historical fork, or `--to-block <number>` to query
  the fork active at a historical block. For a custom network, pass its genesis JSON as
  `--chain` so the command checks the correct chain ID. Hardfork activations come from
  the endpoint's `tempo_forkSchedule`, including for historical block queries.
  The endpoint must support `tempo_forkSchedule`, `eth_getLogs` and `debug_traceTransaction` with `callTracer`
  and retain the queried history. `--portal` and `--from-block` narrow the search;
  `--chunk-size` controls the log request size (default: 1000 blocks).
  Proofless fallback batches and reverted verifier calls are skipped. Forks before T13 or
  ranges without a successful Nitro submission return an error. These are measurements
  accepted on-chain in the selected fork, not measurements from the local binary or an
  independently approved EIF; the command does not reveal policy before the first Nitro batch.
