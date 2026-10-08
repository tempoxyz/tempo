# Experimental ML-DSA OIDC account authorization

This development branch composes the TIP1130–1133 OIDC work with TIP1113 account
migration. It implements an experimental proof scheme, not a production protocol.

* Scheme and address namespace `0x80`: ML-DSA-65 JWT verification in a RISC Zero guest.
* Primitive signature `0x80 || public_key[1952] || signature[3309]`, pure FIPS 204
  ML-DSA-65 with empty context. Access-key algorithm is **4**; algorithm 3 is multisig.
* Native composite STARK receipts only: fake, Groth16, unresolved assumptions, wrong
  images, and mismatched journals are rejected. SDK/verifier version is pinned to 3.0.5.
* Private inputs: token, identity salt and nonce blinding. Public journal: scheme,
  issuer hash, signing-key hash, address seed, access-key ID, issued-at and valid-until.
* Issuer/key/identity/nonce hashes use domain-separated SHA-256 with u32 big-endian
  length prefixes. Field outputs clear the top three bits. Access-key addresses use
  the last 20 bytes of Keccak-256 over `0x80 || public_key`.

The guest checks canonical compact JWT encoding, `alg=ML-DSA-65`, issuer, audience
and subject, and binds its nonce to the access key, expiry and blinding. It rejects
windows over 3600 seconds and authorizations outside the token lifetime.

## Build and run

Install the RISC Zero Rust toolchain (`rzup install rust`) and the normal Tempo
prerequisites. From this repository:

```sh
cargo test --manifest-path pq/Cargo.toml --features verify
cargo run --manifest-path pq/methods/Cargo.toml --bin export -- guest.elf pq-genesis.json
cargo build --bin tempo
cargo run --bin tempo -- node --dev --dev.block-time 1s --chain ./pq-genesis.json \
  --http --http.port 8545 --http.api all \
  --rpc.max-request-size 20 --rpc.max-response-size 20 \
  --txpool.max-tx-input-bytes 17000000 --txpool.max-tx-gas 200000000 \
  --faucet.enabled \
  --faucet.private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --faucet.amount 1000000000000000 \
  --faucet.node-address http://127.0.0.1:8545 \
  --faucet.address 0x20c0000000000000000000000000000000000000
```

The faucet uses the well-known public Anvil development key already authorized
in the development genesis. Keep this profile on a disposable local chain.

The export command prints the image ID and writes a development genesis with it in
`config.zkVerifyingKeys["128"]`. It also enables `accountMigrationTime=0` and reserves
the development recovery factory required by TIP1113. Native receipts use an explicit
`experimentalPqTxGasLimit=200000000` and `generalGasLimit=400000000` in this
genesis. The transaction override requires both T14 and a configured scheme 0x80
image; other chain configurations retain the ordinary transaction cap. Use that same ELF/image in the prover and demo.
The chain activates ML-DSA and scheme `0x80` only when this image is configured and
T14 is active. Never reuse an existing chain database with a different genesis.

The guest bounds credentials to one hour from the issuer timestamp, also bounded
by the signed token expiry. The demo leaves a one-minute margin.

Native receipts are bounded to 8 MiB. A ZK signature has a 10 million gas verification
charge plus 16 gas per proof byte; ML-DSA verification is charged 100,000 gas plus
16 gas per public-key/signature byte. These are prototype bounds, not calibrated
production pricing. RPC and txpool limits must accommodate the proof.

See the sibling `oidc-prover/pq/README.md` and `oidc-demo/README.md` for the service
and browser setup. Run on a disposable chain ID 1337; the demo blocks other chains.

## TIP1113 migration

A direct secp root calls `upgradeAccount` with a version-one, one-owner multisig
configuration naming the new OIDC account. The original account address, balances,
nonces and existing grants survive. Native multisig owner approvals accept a ZK
signature over the multisig domain digest; the handler verifies publisher state,
access-key possession, time bounds and every owner proof before executing calls.

The migration envelope contains only the upgrade call. The primitive root becomes
retired, while retained classical admin/access keys require explicit revocation.
Keep the full public multisig configuration: the chain stores its commitment and
cannot reconstruct the configuration for recovery. At most two ZK credentials are
accepted per transaction, including key-authorization and multisig owner proofs.

## Security limits

ML-DSA removes the classical signature dependency in issuer tokens and device keys.
This does not establish a 128-bit post-quantum security claim for the complete system.
Tempo's 160-bit account identifiers, truncated hashes, publisher administration,
issuer authentication/recovery, TLS and validator consensus need independent review.
The migrated account retains its original 160-bit identifier.

The prover sees all private witnesses. Composite receipts leak execution length;
RISC Zero also documents limits on its formal zero-knowledge argument and estimates
96-bit soundness for its RISC-V prover. See its [security model](https://dev.risczero.com/api/security-model).
Do not treat the development gas schedule, JSON proof encoding or this unaudited
integration as production-ready.
