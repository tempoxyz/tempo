# tempo-xtask

A polyfill to perform various operations on the codebase.

Subcommands currently supported:

+ `generate-config`: generates a set of validators to run a local network.
+ `replay-dkg`: replays a DKG ceremony for a given epoch by fetching blocks from RPC and using `dkg::observe`.
+ `inspect-block`: inspects a block's extra_data field to determine its contents (dealer log, DKG outcome, etc.).
