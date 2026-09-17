# Portable prebuilt execution

The optional `prebuilt_v1` route retrieves exact private Actions artifacts and never
compiles Tempo, workload tools, or snapshot generators on the benchmark runner.
The ordinary build path retains its 65,536 MiB guard. Prebuilt admission instead
requires 49,152 MiB of capture headroom **plus** every frozen ZIP and extracted
member size and a 1 MiB metadata allowance. All five reserved slots remain subject
to the existing complete setup-failure accounting and deterministic election.

A reviewed successful producer must supply the exact `prebuilt-plan.json` and its
workflow environment digest before this branch can run. No placeholder artifact
is accepted. The plan binds each arm to an immutable manifest, producer attempt,
artifact ID, ZIP digest and sizes. Duplicate JSON/ZIP entries, unsafe archive
members, mismatched manifests, unexpected ABI or unsupported CPUs reject the run.
The CPU checker covers every inherited CPU; both validator masks must be subsets.
Loader overrides are rejected. Each phase rechecks binary hashes and affinity.

The build contract is Rust 1.98.1, profiling Tempo with the explicit three
features, and x86-64-v3 code generation. C/C++ also use the reviewed `NO_PCLMUL`
fallback because v3 does not require that instruction. Workload tools are locked
release builds under the same target contract. These measurements must remain
separate from historical native-target measurements. Comparison arms must agree
on compiler, target, tools and all fixed code-generation settings.

Snapshot metadata must already be present before process cleanup/restoration and
must remain ready after restoration. Missing metadata, force-bloat, unsupported
profilers or environment overrides cannot fall back to generation or compilation.
Normal snapshot restore, verified Tempo regenesis, tuning restoration, kernel
capability/marker checks, strict capture cutoffs and privacy gates remain active.

Each archived phase contains `prebuilt-admission.json`: only artifact/hash bindings,
the exact capacity proof and closed CPU success/count data. Private runner paths
and affinity IDs remain outside the capture. The external controller independently
binds source, producer provenance, capacity receipts and the archived sidecar.
