# Tempo Earn execution presets

`--preset vault-deposit` measures approval plus a UserVault deposit;
`--preset vault-withdraw` measures share approval plus redemption. Both use
pathUSD, three-argument slippage-protected calls, sponsored fees, and one ordered
nonce lane per user. Each operation is an atomic multicall template; it has no
sequence receipt barrier or short expiry that would discard queued work under load.
The helper completes setup before generating the full target TPS times duration
transaction count, then checks inclusion and success using block receipts after
the pool drains. A run can take longer than the requested duration when achieved
throughput is below the target.

Use a fresh chain-1337 benchmark snapshot for every run. Deployment nonces,
derived contract addresses, and TIP-403 policy 2 are fixed by the fixture.
The helper rejects an already-used deployer or policy counter. The presets
support 1–100000 users; account indices 100000 and 100001 are reserved for the
fee payer and deployer. Withdraw setup gives each user shares before measurement.
The oracle price is fixed for this execution benchmark.
