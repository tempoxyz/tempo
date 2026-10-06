# Experimental OIDC signer development

This branch implements the TIP-1132 key publisher and offchain OIDC helpers as dependencies of
[TIP-1130](https://github.com/tempoxyz/tempo/pull/8127). It is not a working OIDC
wallet: TIP-1131 signatures and the TIP-1133 circuit, circuit witness generator, prover,
and verifying key remain unimplemented. No provider token or ZK proof is accepted.

The native publisher is available only when compiling with `experimental-oidc`
and running chain ID `1337`. Default builds and other chain IDs do not register
the precompile. This is not a production hardfork activation.

```bash
cargo build --release -p tempo --bin tempo --features experimental-oidc
./target/release/tempo node --dev --http --http.addr 127.0.0.1 --http.port 8545
```

The publisher address is `0x1132000000000000000000000000000000000000`.
Use `IKeyPublisher` from `tempo-contracts` for typed calls. Its owner, active-list,
and expiry mappings occupy Solidity-compatible slots 0, 1, and 2. Dropped keys
remain valid for 3,600 seconds, inclusive of the expiry timestamp; revoked keys
become inactive immediately. Only the current publisher owner may mutate it.

```bash
cast call 0x1132000000000000000000000000000000000000 \
  'computePublisherId(address,bytes32)(bytes32)' \
  0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
  0x000000000000000000000000000000000000000000000000000000000000002a \
  --rpc-url http://127.0.0.1:8545

cargo test -p tempo-precompiles key_publisher --lib --features test-utils
cargo test -p tempo-precompiles key_publisher --lib --features experimental-oidc,test-utils
```

Run the receipt-checked live smoke test against an experimental node with the
standard funded development account:

```bash
bash scripts/oidc-devnet-smoke.sh http://127.0.0.1:8545
```

It checks publisher creation, rotation and the 3,600-second grace deadline,
revocation, owner transfer, rejection of malformed keys and unauthorized calls,
and an ordinary TIP-20 payment. Every state-changing call checks its mined
receipt. The script only accepts loopback URLs and verifies chain ID 1337 before
sending transactions with the publicly known development key. It does not test
OIDC authorization, and it never uses the Centaur wallet.

`examples/oidc` supplies circomlib Poseidon hashing, nonce and address derivation,
HMAC salt derivation, local RS256 token preflight, and a JWKS-to-`setKeys`
transaction planner. Its tests use synthetic provider-signed tokens and shared
seven-input vectors from the native verifier in
[PR #8137](https://github.com/tempoxyz/tempo/pull/8137). Offchain preflight does
not prove the relation; the circuit must independently enforce every constraint.
Neither that PR nor this one currently supplies the TIP-1133 circuit or its key.

Do not use real funds or identities. Keep RPC private. A public provider sign-in
demo also needs a separately registered OAuth client and a Relay API; no
credentials are embedded in this branch.

## Remaining end-to-end acceptance criteria

- Implement TIP-1133's exact RSA, JSON, base64url, Poseidon, and nonce-binding
  constraints, including negative vectors and independent circuit review.
- Produce a clearly labeled devnet-only setup and verifying key, and publish the
  circuit, constraint hash, and shared proving/verification test vectors. The
  production ceremony and audits specified by TIP-1133 are separate prerequisites.
- Implement canonical TIP-1131 `0x06` encodings, proof validation, address and
  digest derivation, expiry, signature limits, gas, and accepted signing contexts.
- Check publisher state at the transaction's execution position, including a
  rotation or revocation earlier in the same block, and handle pool revalidation.
- Run provider discovery/key synchronization, a stable salt service, a prover,
  and a wallet that binds the provider nonce to a newly generated device key.
- Demonstrate provider sign-in, proof-authorized device-key installation, funded
  TIP-20 payment without another proof, revocation, and replay/expiry rejection.
- Verify configurable-account owner approvals when TIP-1114 is integrated, while
  preserving standalone OIDC signers without configurable accounts.

The precompile, signature scheme, and circuit must activate together in the
eventual production hardfork. This experimental feature is not that activation.
