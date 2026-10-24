# Zones and Earn with JIT

Build the node with Cargo feature `jit` and pass `--jit` at runtime. This branch's
`public-mix` preset includes Zone deposits/withdrawals and Earn vault deposits/withdrawals.
JIT dispatch preserves Tempo's SSTORE storage-credit accounting. The revmc dependency
pins the context hook in https://github.com/paradigmxyz/revmc/pull/425.

For a same-code interpreter/JIT comparison, dispatch from this branch and use its
commit for both node revisions:

```bash
bench_branch=$(git branch --show-current)
bench_revision=$(git rev-parse HEAD)
gh workflow run bench-e2e.yml --repo tempoxyz/tempo --ref "$bench_branch" \
  -f baseline="$bench_revision" -f feature="$bench_revision" \
  -f preset=public-mix -f feature-args='--jit --jit.hot-threshold 1' \
  -f duration=90 -f run-pairs=3 -f bloat=100 -f tps=50000 \
  -f accounts=1000 -f max-concurrent-requests=100 -f otlp=false \
  -f txgen-ref=992d083c7d95a071c6cda238d2d83bf5bcb84969
```

The workflow installs LLVM 22 if necessary and builds both sides with JIT support;
only feature nodes enable it. Runtime logs report compilation successes/failures,
compiled-code lookup hits, and interpreter misses. A successful workflow alone does
not prove JIT execution: check for nonzero hits and successful compilations.
For a low-rate verification run, enable `tempo::jit::execution=trace` in the node's
log filter to record the bytecode hash of each compiled dispatch.

Local runs on a configured benchmark runner use:

```bash
nu bench-e2e.nu e2e --baseline "$bench_revision" --feature "$bench_revision" \
  --preset public-mix --features jit --feature-args '--jit --jit.hot-threshold 1' \
  --duration 90 --run-pairs 3
```

JIT currently uses the latest configured Tempo fork's gas schedule. Other forks,
the opt-in Amsterdam state-gas mode, and inspector-based tracing use the interpreter.
Native precompiles continue to execute their native implementations.
