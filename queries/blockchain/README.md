# Bifrost blockchain audit queries

These are [Bifrost RQL](https://github.com/BrokkAi/bifrost/blob/master/docs/src/content/docs/rune-query-language.md) queries (`.rql`, not CodeQL `.ql`). They search Rust source for *review leads*, not proven exploit paths. From the repository root, with Bifrost installed (`uv tool install brokk-bifrost`):

```sh
for query in queries/blockchain/*.rql; do
  echo "=== $query"
  bifrost --root . --workspace-scaled-limits --query-file "$query"
done
```

The results are JSON under `structuredContent.results`. Check `structuredContent.truncated` and `structuredContent.diagnostics` before interpreting a zero count. Some queries also match tests, and names alone do not establish the called function's identity, reachability, or the safety of its result.

## Initial triage

Run against Tempo `f2c82d1539` with Bifrost 0.12.0. All seven queries completed without truncation or diagnostics:

| Query | Matches | What to review |
| --- | ---: | --- |
| `panics-in-critical-paths.rql` | 25 | Panics on block, DKG, follower, and EVM paths |
| `unchecked-consensus-blocks.rql` | 13 | Blocks reconstructed without checking their sidecars |
| `saturating-value-accounting.rql` | 50 | Silent underflow/overflow in fees, credits, and fills |
| `wrapping-value-accounting.rql` | 4 | Intentional modulo operations versus monetary wrap |
| `narrowing-in-economic-code.rql` | 13 | Casts that might truncate values (assignment-text heuristic) |
| `decoding-inside-loops.rql` | 8 | Repeated parsing of potentially attacker-controlled input |
| `signature-verification-sites.rql` | 5 | Verify/recover call sites; inspect how failures are handled |

### Code-path finding: BAL sidecar omission can panic during follower resolution

**Conditional denial of service; existing FIXME in the code.** With the optional `bal` feature enabled and a block whose header contains a BAL hash, the [follower resolver](../../crates/consensus/src/follow/resolver/mod.rs) reconstructs persisted/upstream execution blocks with `Block::from_execution_block_unchecked(block, None)`, then encodes them in `resolve_block` or `resolve_finalized`. `Block::encode_size` and `Block::write` call `expect` when the hash is present but the sidecar is `None` ([block encoding](../../crates/consensus/src/consensus/block.rs)). Thus resolving such a block takes a panic path instead of returning a retryable error. The source already documents this as a FIXME; the normal binary build does **not** enable `bal`. I traced the path statically, but did not run a BAL-enabled reproduction or establish a network-attacker-controlled trigger.

To address it, restore and validate the BAL sidecar before creating a block intended for encoding (as `storage/hybrid` already does), or refuse sidecar-less encoding without panicking. The other leads sampled here did not establish another vulnerability. In particular, the V1 validator-count cast to `u8` is an explicitly accepted 255-validator migration limit in [TIP-1017](../../tips/tip-1017.md), not an independently confirmed exploit. This is a targeted source audit, **not** a claim that every match or every security-sensitive path was reviewed.
