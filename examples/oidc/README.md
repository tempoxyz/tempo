# Experimental OIDC tooling

This example implements TIP-1133's offchain hashing and token preflight, not its
proof circuit. It cannot produce a proof or authorize an onchain account.
The node continues to reject signature type `0x06`. Do not use real identities,
funds, or production secrets with this experimental example.

```bash
npm ci --ignore-scripts
npm test
node publisher.mjs --jwks keys.json --issuer https://accounts.google.com \
  --publisher-id <bytes32>
```

`publisher.mjs` reads an already retrieved, trusted provider JWKS file. It emits a
transaction plan only and never sends it. It computes circomlib Poseidon hashes
of 2048-bit RSA moduli, deduplicates and sorts them, and ABI-encodes the native
publisher's `setKeys` call. Review the issuer, publisher ID, keys, and target
network before using the plan. Empty or unsupported signing-key sets fail closed
instead of clearing an issuer's keys. Provider discovery and automatic polling
are not implemented.

`oidc.mjs` exports issuer, identity, nonce, public-input, and address derivation;
the Relay API's HMAC salt derivation; and `tokenWitness`. The latter verifies a
genuine RS256 signature with Node's crypto implementation, enforces compact
JSON with unique unescaped top-level claims, and checks the issuer, audience,
nonce, times, and size bounds before returning private witness material. It uses
the caller-supplied trusted provider key, expected issuer and audience, current
timestamp, device-key ID, expiry, salt, and blinding. It does not fetch keys or
take a token's issuer as a trusted discovery URL.

Persist a randomly generated salt secret in a durable secret store before
building a Relay API: changing it changes every user's address. Never put that
secret, provider tokens, private witness output, or identity claims in logs.
`stableSalt` is a cryptographic helper, not a deployed salt service. Every
`tokenWitness` constraint must also be enforced inside the eventual circuit:
offchain preflight is not a proof of the relation. Its return shape is not yet a
circom witness ABI, and no circuit hash, setup, or verifying key is supplied.

The tests use locally generated 2048-bit RSA keys and signed synthetic tokens,
not a Google/Apple sign-in. They cover circomlib's Poseidon reference vector,
hashing bounds, identity separation, private witness padding, key rotation
plans, and malformed/replayed/expired token rejection. Circuit cross-language
vectors and end-to-end login remain acceptance criteria in `docs/oidc-devnet.md`.

Poseidon uses the dependency-free `poseidon-lite` implementation, checked against
32 frozen circomlibjs 0.1.7 vectors covering every supported arity and the native
verifier's boundary vectors. It uses JavaScript BigInt and is not constant-time
or audited: keep these helpers out of multi-tenant production services until
reviewed. RS256 checks use Node crypto and calldata uses ethers v6. These tests
do not constitute a security audit or approval for production use.
