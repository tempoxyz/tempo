# tempo-xtask

Zones tooling is available through `cargo zone-xtask` (the `tempo-zone-xtask`
binary). See the [Zones command reference](src/zones/README.md).

A polyfill to perform various operations on the codebase.

Subcommands currently supported:

+ `generate-config`: generates a set of validators to run a local network.
+ `add-hardfork --hardfork T11`: generates the mechanical plumbing for a new hardfork and rotates
  the `default`/`next` Foundry profiles.
+ `get-verifier-pcr-policy --chain moderato [--rpc-url <url>] [--hardfork T13]`:
  queries `tempo_getVerifierPcrPolicy` for the serving L1 node's expected PCR0/1/2,
  even before any successful Nitro batch. Omitting `--hardfork` selects the active
  fork at the returned head block; an explicit fork must have activated on that
  network. JSON includes the chain ID, head hash/timestamp, selected policy and
  per-fork policy history. `pcrs: null` means no approved Nitro measurements (also
  before T13), not zero-valued PCRs. Unchanged PCRs are inherited across forks.
  The command checks the selected chain ID and requires an upgraded node; it
  never substitutes this CLI's compiled policy when the RPC is unavailable.
  Results reflect the serving node's configuration, including custom development
  PCR overrides, not a cryptographic state proof or an emitted event history.
  Historical entries describe that node's current policy for earlier forks,
  not the software/configuration a node ran in the past. Compare against an
  independently trusted release/EIF when checking an untrusted endpoint.
