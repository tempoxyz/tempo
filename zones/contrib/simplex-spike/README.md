# Simplex-for-zones type-check spike

Standalone crate (its own `[workspace]`, not a member of the root workspace) that type-checks the
commonware 2026.9.0 composition proposed in `/simplex.md` §6: `simplex::scheme::ed25519::Scheme`,
`elector::RoundRobin`, `marshal::standard::{Standard, Inline}`, `marshal::core::Actor` over an
`immutable::Archive` of finalizations and a `prunable::Archive` of blocks, `buffered::Engine`,
`marshal::resolver::p2p`, and `simplex::Engine`, with a mock block in place of the zone `Block`
wrapper and a static manifest-backed `commonware_p2p::Provider`.

```
cd zones/contrib/simplex-spike && cargo check --offline
```

Nothing runs; `main` only prints. See `/simplex.md` Appendix A for the signature notes this
spike produced.
