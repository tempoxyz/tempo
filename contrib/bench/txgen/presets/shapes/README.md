# Deployment shapes

A deployment shape describes how one customer deployment uses Tempo, in a form that
both capacity benches and the integrations site can share: which pillar it belongs
to, which flows it runs, how much traffic it sends and which bench templates
implement each flow. Name shapes and flows by traffic shape, never by customer or
partner. `schema.json` is the JSON Schema; `examples.yml` holds one shape per pillar.

```yaml
version: 1
shapes:
  - name: remittance-payout          # traffic shape: lowercase letters, digits, hyphens
    pillar: cross-border             # cross-border | institutional | embedded-finance | agentic
    description: Corridor payouts with FX conversion and cash out.
    volume:
      tx_per_month: 3000000          # on-chain transactions per 30-day month
      peak_factor: 3                 # peak TPS over average TPS (default 1)
    share: 9000000                   # optional gas share in a combined run
    flows:                           # flow name -> gas weight and implementing templates
      corridor_payout: {weight: 30, templates: [public_transfer_memo]}
      payroll: {weight: 20, templates: [payroll_existing, payroll_new]}
      cash_out: {weight: 20, templates: [cash_out]}
    presets: [batch-payout, dex]     # optional: presets that stress these flows alone
```

Pillars:

| pillar | covers |
|---|---|
| `cross-border` | remittance, global payouts, payroll |
| `institutional` | tokenized deposits, institutional settlement, treasury |
| `embedded-finance` | stablecoin accounts, pay-ins and payouts, cards and Earn in products, neobanks |
| `agentic` | MPP and agent payments |

Flow templates are `neobank-generic` templates (its header lists each one, grouped
by module). A flow's weight is a gas share within the shape and is split evenly over
its templates; give a template its own flow for exact control. `presets` points to
dedicated presets for flows `neobank-generic` only approximates, such as MPP channels
(`mpp`) or policy-checked transfers (`tip20-policy`).

## Running a shapes file

`neobank-multi` reads a shapes file wherever it reads an instances file: each shape
becomes one instance, with the modules its templates belong to, its flow weights
(other templates in those modules get weight 0) and its share. Without `share`, a
shape's share is its peak transaction rate (`tx_per_month * peak_factor`), a
transaction-rate stand-in for gas share; set `share` when the gas split is known.

```
derek bench preset=neobank-multi gas-limit=500M general-gas-limit=30M bench-env="TXGEN_NEOBANK_INSTANCES=contrib/bench/txgen/presets/shapes/examples.yml"
```

The helper prints the shapes' combined peak target, the sum of
`tx_per_month / 2592000 * peak_factor` per shape. Headroom is the bench's sustained
TPS for that mix over this target.
