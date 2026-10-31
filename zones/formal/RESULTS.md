# Initial experiment

Tested on 2026-10-21 against `ec79472dfd3fe01dbf4a0e43d1bc19512afa21da`
plus this change. No production implementation changes are included.

| Check | Result |
| --- | --- |
| TLC bounded safety search | 6,022 generated states, 2,646 distinct, depth 17; all six invariants passed |
| Native precompile library suite | 164 passed, 1 ignored, 0 failed |
| New portal scenarios | 4 passed, 0 failed |
| Recorded-state conformance | 8 scenarios, 80 observations; all accepted |
| Corrupted final observations | All 8 rejected with replay deadlocks |
| Real implementation mutation | Omitting fallback-recipient deletion was rejected at bounce-back import |
| Rust and Solidity formatting | Passed for the changed surfaces |

Tooling: Rust 1.95.0, Foundry 1.8.5, TLC 2.19 from the official
`tlaplus/tlaplus` v1.7.4 release, and OpenJDK 21. Native tests ran on a temporary
boxctl machine; Foundry and TLC ran in the sandbox. The wrapper's shell syntax
was checked; its constituent commands were executed on these separate machines.

## Implementation mutation

In the temporary build checkout only, remove
`self.fallback_recipients[nonce].delete()?;` from
`ZoneOutbox::consume_fallback_recipient` and run:

```sh
cargo test --locked -p zone-precompiles --lib tla_native_lifecycle_traces -- \
  --nocapture --test-threads=1 > mutant.log
uv run python zones/formal/check.py --jar "$TLA2TOOLS_JAR" --trace mutant.log
```

The native scenario test completes, but replay exits nonzero with
`Error: Deadlock reached.` in `native-bounce-mint`: after importing the bounce,
the observed `fallbackCount` is still 1, while the specification requires 0.
The preceding successful-withdrawal scenario passes because successful Tempo
delivery intentionally retains the zone-local mapping. Restore the deleted line
after the experiment. This mutation is not present in this change.

This demonstrates sensitivity to one implementation/specification disagreement.
It is an injected defect, not a discovered production bug. The checked scenarios
found no disagreement in the unmodified implementation. See the README's scope
limits before interpreting that result as wider assurance.
