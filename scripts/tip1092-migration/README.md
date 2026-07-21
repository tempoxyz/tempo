# TIP-1092 migration

These scripts migrate every historical TIP-20 token on Presto mainnet or Moderato testnet into
the TIP-403 transfer-policy registry, then independently verify the result.

The migrator scans `TIP20Factory.TokenCreated` logs in bounded ranges, includes the genesis tokens
that have no creation logs, batches registry calls, and submits several transactions concurrently
with expiring nonces. Each transaction and log query is retried with exponential backoff. Progress
is checkpointed only after every transaction for a block range is confirmed, so an interrupted run
can safely resume from the same state file. The migration precompile is idempotent.

Set the signer through the environment so it does not appear in shell history:

```bash
export TEMPO_PRIVATE_KEY=0x...
./scripts/tip1092-migrate.sh --network testnet
./scripts/tip1092-verify.sh --network testnet --report tip1092-testnet-report.ndjson
```

For mainnet, make the target explicit:

```bash
./scripts/tip1092-migrate.sh --network mainnet
./scripts/tip1092-verify.sh --network mainnet --report tip1092-mainnet-report.ndjson
```

Both commands select the repository's canonical RPC URL and reject a chain-ID mismatch. Use
`--rpc-url` to point at an archival or higher-capacity endpoint. The verifier scans independently
through the latest block captured at startup, checks `tokenTransferPolicyId` for every token, and
exits nonzero if any binding is unset or any lookup fails.

Useful tuning options:

- `--batch-size`: token addresses per migration transaction (default `128`)
- `--max-in-flight`: concurrent expiring-nonce transactions (default `4`)
- `--scan-blocks`: initial log-query range; failures automatically halve it (default `50000`)
- `--max-retries`: RPC/transaction retries (default `5`)
- `--state-file`: durable migration checkpoint path
- `--concurrency`: concurrent verification calls (default `64`)
