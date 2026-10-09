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

The serial benchmark compares full state-root construction and incremental updates for
mass payouts and repeated transfers among a small holder set. It includes holder
EOAs, token accounts and the additional inert storage accounts, and uses Reth's
trie implementation with in-memory cursors. It does not measure database I/O,
disk footprint, proof sizes or end-to-end block execution. Account creation and
code-deposit gas must also be evaluated before selecting a production design.

## Bare-metal results (October 6, 2026)

Measured on boxctl plan `f4-metal-small` in `FRA2`, with Rust 1.99.0, release
optimization, LTO disabled, 10 samples, 1-second warmup and a 2-second measurement
target. Values below are Criterion's central time estimates, rounded to
milliseconds. The small-holder workload modifies 16 balances; the payout workload
modifies 4,096 balances (one payer and 4,095 existing recipients). Every holder
already has a nonce-bearing EOA; the holder-first variant adds an inert companion
account. All holders own every token in the fixture.

| Holders | Tokens per holder | Root workload | Token-first (ms) | Holder-first (ms) |
| --- | --- | --- | --- | --- |
| 10,000 | 1 | Full rebuild | 8.817 | 21.523 |
| 10,000 | 1 | 16-balance update | 0.227 | 0.245 |
| 10,000 | 1 | 4,096-balance payout | 4.021 | 19.307 |
| 10,000 | 4 | Full rebuild | 17.723 | 34.263 |
| 10,000 | 4 | 16-balance update | 0.229 | 0.296 |
| 10,000 | 4 | 4,096-balance payout | 4.026 | 29.129 |
| 100,000 | 1 | Full rebuild | 107.180 | 259.150 |
| 100,000 | 1 | 16-balance update | 0.275 | 0.329 |
| 100,000 | 1 | 4,096-balance payout | 17.271 | 49.751 |

For 100,000 holders and one token, a payout changes 18 cached account-trie branch
entries and 3,325 storage-trie branch entries in the token-first variant, versus
4,162 account-trie branch entries and no storage-trie branch entries in the
holder-first variant. These are retained branch-cache entries, not all trie nodes
or database byte counts. Incremental roots were checked against full rebuilds
before timing every workload.

This companion-account design is slower in the measured serial, in-memory root
path despite shrinking individual storage tries. These results do not establish
performance for parallel root calculation, disk-backed state, protocol-isolated
storage directly on holders, or first-time recipients. No block-throughput or
production performance improvement is claimed.
