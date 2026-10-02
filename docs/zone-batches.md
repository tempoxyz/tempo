# Sample historical Zone PCRs by hardfork

`tempo zone-pcr-history` reports one successful direct Nitro submission's
PCR0/1/2 tuple per T13-or-later hardfork interval, newest first.

```sh
tempo zone-pcr-history --rpc-url http://localhost:8545 > pcr-history.json
```

The RPC must provide `tempo_forkSchedule` and historical transactions, blocks,
and logs. Intervals use the node's activation schedule, including custom chains;
future and empty intervals are skipped. Portal discovery reads the factory at the
upper block bound using `nextZoneId()` and Multicall3 `zones(id)` calls; Multicall3
must be deployed unless `--portal` is supplied.

## Optional filters

```sh
tempo zone-pcr-history \
  --rpc-url "$RPC_URL" \
  --portal "$PORTAL" \
  --from-block 100000 \
  --to-block 110000
```

- `--portal`: inspect one portal instead of querying all registered factory portals.
- `--from-block`: inclusive lower bound; defaults to zero.
- `--to-block`: inclusive upper bound; defaults to latest at startup. Use a
  finalized block for stable results; the scanner does not detect reorgs.

## Output

```json
[
  {
    "hardfork": "T14",
    "observed_pcrs": ["0x...PCR0...", "0x...PCR1...", "0x...PCR2..."]
  }
]
```

`observed_pcrs: null` means no qualifying submission was found in the selected
range for that hardfork. JSON is written only when the entire scan succeeds.

## Limitations

- Samples only T13 `BatchSubmitted` events and direct `submitBatch` calls with
  `verifierConfig == 0x01`, including Tempo AA calls.
- Assumes accepted Nitro submissions within each interval share the same PCR tuple.
- Trusts the portal's configured verifier to validate Nitro attestations and
  enforce the PCR policy when settling batches.
