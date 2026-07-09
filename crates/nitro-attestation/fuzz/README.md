# TIP-1090 fuzzing

`parse_attestation` feeds arbitrary COSE/CBOR documents into the consensus parser. Whenever the
structural parser extracts certificates, it also runs `x509-parser` and `rustls-webpki` over every
DER value. If Tempo accepts the complete non-cryptographic X.509 profile, both independent parsers
must accept the same certificates and `rustls-webpki` must also accept the pinned root as a trust
anchor.

Signature checks are intentionally stubbed so mutations can reach the certificate-profile logic;
SHA-384 hashing remains real.

Run the target with a nightly toolchain and `cargo-fuzz`:

```sh
cargo install cargo-fuzz
cd crates/nitro-attestation
cargo +nightly fuzz run parse_attestation -- -max_len=24577
```

The package is excluded from the root workspace so it keeps its fuzz-only dependency graph and
build settings isolated from node releases.
