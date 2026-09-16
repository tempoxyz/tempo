# Workload display metadata

Send `workload_mix_version=1` and `workload_mix_weights=<JSON object>` through
`bench send -m`. The object maps category names to aggregate non-negative numeric
selection weights, for example:

```json
{"mpp_open_only":15,"public_mint":5,"public_transfer":80}
```

Calculate this from the prepared mix, after fixture expansion. Strip only the
numeric account suffix in `zone_deposit_N`, `zone_withdraw_N`, `vault_deposit_N`,
and `vault_withdraw_N`, and sum the weights for each category. Preserve all other
names, including sequence names. Keys are sorted for deterministic output.
Percentages are `100 * category_weight / total_weight`; they describe workload
selections, not transaction counts within multi-transaction sequences.

Keep other scalar run metadata. Do not send the expanded mix as `mix` metadata;
keep the full spec as txgen input and in benchmark artifacts. The multi-region
sender in `tempoxyz/tempo-multi-region-benchmark` must adopt the same contract.
Historical `mix` arrays remain readable by the companion dashboard change.

Run `nu --no-config-file contrib/bench/txgen/workload-metadata-test.nu` to verify
aggregation, bounded output, invalid inputs, includes, and fixture overrides.
