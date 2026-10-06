# Holder-first TIP-20 balance experiment

Build with `--features tempo-precompiles/holder-first-balances` to store TIP-20
balances in one deterministic storage account per holder instead of in each
token's storage. The default build retains the existing layout and behavior.
This is a consensus-breaking experiment for fresh genesis state only: **do not
enable it against an existing chain or database**. No migration or hardfork
activation is implemented.

The storage account address is the last 20 bytes of
`keccak256("tempo.tip20.holder-balances.v1" || holder)`. Its balance slot is
`keccak256(bytes32(token) || bytes32(holder))`. Including the full holder in the
slot separates balances even if two holders' derived storage addresses collide.
The first nonzero write installs a one-byte `STOP` runtime. A nonempty conflicting
account is rejected rather than overwritten. Holder contracts use different
storage and cannot modify this account's balances; the inert runtime has no
storage-writing or destruction instructions.

Token metadata, supply, allowances, permits and reward accounting retain their
existing token-owned layout. Fee validation, fee-payer balance caching and
non-creditable fee balance identification use the physical storage address.
Storage credits otherwise follow the physical storage-owning account; adapting
credit ownership and authorization is required before production activation.
The legacy state-bloat generator and genesis storage overrides encode the old
layout and must not be used to seed this experiment. Seed through TIP-20 methods.

Run both layouts' state-root benchmarks on the same machine:

```sh
cargo bench -p tempo-evm --bench tip20_balance_layout
cargo test -p tempo-precompiles --lib --features test-utils
cargo test -p tempo-precompiles --lib --features test-utils,holder-first-balances
cargo test -p tempo-revm --lib --features tempo-precompiles/test-utils,tempo-precompiles/holder-first-balances
```

The benchmark compares full state-root construction and incremental updates for
mass payouts and repeated transfers among a small holder set. It includes holder
EOAs, token accounts and the additional inert storage accounts, and uses Reth's
trie implementation with in-memory cursors. It does not measure database I/O,
disk footprint, proof sizes or end-to-end block execution. Account creation and
code-deposit gas must also be evaluated before selecting a production design.
