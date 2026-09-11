# Executed V2 account-root benchmark results

Executed on the implementation committed with these artifacts; see git history for the exact code revision.
Stack: configurable-account activation (`joshie/configurable-activation`) → carried V1 → V2 root.

3,456 V2 matrix receipts, 28 successful edge receipts plus four oversized-certificate rejections,
18 failed-batch receipts, and a freshly executed 1,728-row stored/V1 baseline. Every V2 execution
asserts no persistent AccountKeychain writes and checks the receipt-reconstructed tree against R.

## Representative costs

Configurable 1-owner secp256k1 parent, primitive secp256k1 delegate; one active policy; registered parent; self-paid.

| Policy | Stored first | V1 first | V2 first | V2 repeat | V2 later |
|---|---:|---:|---:|---:|---:|
| Unlimited | 301,626 gas / $0.003620 | 47,002 gas / $0.000565 | 53,067 gas / $0.000637 | 51,062 gas / $0.000613 | 51,062 gas / $0.000613 |
| Lifetime cap | 804,313 gas / $0.009652 | 313,717 gas / $0.003765 | 78,900 gas / $0.000947 | 76,903 gas / $0.000923 | 76,903 gas / $0.000923 |
| Periodic cap | 804,413 gas / $0.009653 | 316,437 gas / $0.003798 | 79,100 gas / $0.000950 | 77,103 gas / $0.000926 | 77,103 gas / $0.000926 |
| 2 caps + 2 targets | 2,818,513 gas / $0.033823 | 314,741 gas / $0.003777 | 83,400 gas / $0.001001 | 81,379 gas / $0.000977 | 81,379 gas / $0.000977 |

Lifetime-cap first-use gas falls 74.85% versus V1, but reuse costs 10,386 more gas.
Unlimited V1 has no counter allocation to remove and is cheaper than V2 here. Constant account state is not universally the lowest fee.

## Active policies and sponsorship

Lifetime-cap policy, same actors. Fresh=true means an unregistered configuration on an already funded account;
the new-accounts edge separately starts both native account records at nonce zero with empty extensions.

| Active | Self first | Self repeat | Sponsored first | Sponsored repeat |
|---:|---:|---:|---:|---:|
| 1 | $0.000947 | $0.000923 | $0.000759 | $0.000734 |
| 2 | $0.000977 | $0.000953 | $0.000773 | $0.000749 |
| 4 | $0.001008 | $0.000984 | $0.000789 | $0.000765 |
| 8 | $0.001038 | $0.001014 | $0.000804 | $0.000780 |
| 16 | $0.001068 | $0.001044 | $0.000820 | $0.000795 |
| 64 | $0.001135 | $0.001111 | $0.000851 | $0.000827 |
| 256 | $0.001203 | $0.001182 | $0.000884 | $0.000859 |

1,898/3,456 matrix receipts are strictly below the $0.001 reference; **not all cases are cheaper**.
Large quorums, broad policies, multiple calls, fresh configuration and deeper proofs remain explicit costs.
Root commitment removes per-policy counter allocation, not transaction execution, signatures, proof publication, or mutable-root updates.

[Privy's pricing](https://www.privy.io/pricing), checked 2026-09-11, advertises enterprise signatures as low as $0.001.
That is a signature-service-only reference, not a universal price floor: free allowances, custody, issuance signatures,
relay operation and vendor-backed transaction chain fees differ. No total-service-cost or throughput claim is made.

## Measurement scope

Root and main baseline matrix run with basefee=maxFeePerGas=12,000,000,000 attodollars/gas, zero priority fee.
Fees use ceil(gas*price/10^12) microUSD. `bytes` is the complete carried authorization, not the whole transaction.
Policies: 0 unlimited; 1 lifetime cap; 2 periodic cap; 3 two capped tokens plus two target scopes.
Phases: 0 installation+transfer; 1 repeat; 2 later transfer (rollover only for policy 2). Prior unrelated leaves are seeded
fixture state, not free installations. Matrix parents are native 1-owner accounts; all three parent and delegate curves
are crossed with primitive/native delegates, both payer modes, all policies and 1/2/4/8/16/64/256 active leaves.
Unused token limits remain in the committed usage vector; only the transferred/fee token changes.
The 32 edge rows cover maximum-size WebAuthn, 8-owner secp and maximum-WebAuthn quorums, 32 tokens, 32 calls, 120 recipients, new accounts, and late first period.
Eight-owner maximum-WebAuthn carried certificates exceed 4KB and are rejected, not assigned an imaginary successful gas cost.
Failure cases perform a successful first transfer then scope/revert/out-of-gas failure, at 1/4/256 active leaves and both payer modes.

Baseline `execution_us` is debug-build diagnostic timing only; it is not a calibrated performance benchmark.
V2 meter constants are draft candidates; production calibration, independent security review, reorg integration,
a deployed witness service and automatic client proof refresh remain outside this local implementation/receipt validation.

## Validation

Affected library suites: 159 tempo-alloy, 1,019 tempo-precompiles, 283 tempo-primitives and 243 tempo-revm tests passed (1,704 total).
Root matrix/lifecycle run: eight tests passed including both ignored receipt generators. Fresh baseline: three receipt generators passed.
Nightly fmt check and clippy for the four affected libraries passed; existing unrelated clippy warnings remain.
The precompile suite requires `--features test-utils`; without it, existing ABI-conformance test imports are unavailable.

## Reproduce

```sh
CARGO_PROFILE_DEV_DEBUG=0 cargo test -p tempo-revm --lib account_tree --locked -j 4 -- --include-ignored --nocapture > /tmp/tree.log 2>&1
CARGO_PROFILE_DEV_DEBUG=0 cargo test -p tempo-revm --lib carried_cost_ --locked -j 4 -- --ignored --nocapture --test-threads=1 > /tmp/baseline.log 2>&1
uv run scripts/plot-tip-1086-tree.py --root-log /tmp/tree.log --baseline-log /tmp/baseline.log
```

[Implementation and wire rules](tip-1086-tree-implementation.md) · [matrix](tip-1086-tree.csv) · [baseline](tip-1086-tree-baseline.csv)
· [edges](tip-1086-tree-edges.csv) · [failures](tip-1086-tree-failures.csv) · [plots](tip-1086-tree-plots.pdf)
