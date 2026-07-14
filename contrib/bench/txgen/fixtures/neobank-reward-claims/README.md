# Neobank reward-claim fixtures

The neobank Merkl workload uses a generated JSON array rather than embedding
thousands of proofs in the preset. Generate the records and their metadata with:

```console
cargo run -p tempo-xtask -- generate-neobank-reward-claims \
  --wrapper-token 0x878e9282ca9a0fadd5832c2bf933c197f60e4165 \
  --out contrib/bench/txgen/fixtures/neobank-reward-claims/claims.json
```

The wrapper address is the deterministic deployment used by the preset. Changing
its deployer or nonce requires regenerating the fixture and updating the setup
root. The defaults emit 2,048 records for mnemonic indices `0..2048`, amount
`43860`, and account pool `reward_claimants`. Every leaf is
`keccak256(abi.encode(user, wrapperToken, cumulativeAmount))`; parent nodes hash
sorted pairs. A non-power-of-two claim count is padded to the next power of two
with unique mnemonic-derived leaves, but those dummy leaves are not emitted as
records.

`claims.json` is a compact txgen record array. `claims.meta.json` contains the
Merkle root, proof depth, wrapper token, total funding for emitted claims, and
the derivation ranges. Repeated `shuffled_cycle` consumption exercises full
proof verification and the payout path across repeated cycles within the funded
benchmark window because the benchmark-only distributor permits proof reuse.
This intentionally differs from production Merkl cumulative-claim accounting
so every measured transaction executes the complete claim path. The first pass
creates each claimant's persistent claim state; later passes exercise
steady-state updates to those slots.

When `--account-start` is nonzero, configure `reward_claimants` to begin at the
same mnemonic index; each record's `select.index` remains pool-relative.

Check a committed fixture without rewriting it:

```console
cargo run -p tempo-xtask -- generate-neobank-reward-claims \
  --wrapper-token 0x878e9282ca9a0fadd5832c2bf933c197f60e4165 \
  --out contrib/bench/txgen/fixtures/neobank-reward-claims/claims.json \
  --check
```

The records file grows quickly because every row contains complete ABI calldata.
Inspect the byte count printed by the generator before committing a larger pool.
The default 2,048-row fixture is 3,312,556 bytes (3.16 MiB), with an 11-sibling
proof and 772 bytes of calldata per row.
