# Tempo Earn execution presets

`--preset vault-deposit` measures approval plus a UserVault deposit;
`--preset vault-withdraw` measures share approval plus redemption. Both use
pathUSD, three-argument slippage-protected calls, sponsored fees, and expiring
nonces. The helper funds accounts and completes contract and per-user setup
before generating the measured workload, so setup does not consume nonce expiry.

Use a fresh chain-1337 benchmark snapshot for every run. Deployment nonces,
derived contract addresses, and TIP-403 policy 2 are fixed by the fixture.
The helper rejects an already-used deployer or policy counter. The presets
support 1–100000 users; account indices 100000 and 100001 are reserved for the
fee payer and deployer. Withdraw setup gives each user shares before measurement.
The oracle price is fixed for this execution benchmark.
