# Private OIDC sign-in devnet

This example connects the TIP-1133 RS256 circuit and prover to TIP-1131 native
`0x06` signatures and TIP-1132 key publication. It includes a Google sign-in
page, a local nonce/salt/proving relay, and a receipt-checked synthetic-provider
test that installs a device key and makes a second payment without another proof.
The native implementation is stacked on [PR #8137](https://github.com/tempoxyz/tempo/pull/8137).

Everything here is unaudited and for private chain 1337 only. No real funds or
identities. Default node builds have no OIDC verifying key; enabling `oidc-devnet`
only permits an explicitly supplied local key on chain 1337. Production still
requires the TIP-1133 ceremony, independent audits, and hardfork activation.

## Compile and test the circuit

Node 24 or later is required. Dependencies are pinned in the lockfile. RSA and
SHA-256 primitives come from `@zk-email/circuits` 6.3.4; Poseidon uses circomlib
2.0.5 inside the circuit and shared circomlib reference vectors offchain.

```bash
npm ci --ignore-scripts
node compile.mjs build
OIDC_ARTIFACTS=build npm test
```

The tested circuit has 1,366,395 constraints and exactly one public input.
Its compiled R1CS SHA-256 is
`b6aee9040b1dfc8072f57ddd83942c4ae1fadb7a496eb1d2ff9a091429457f36`.
Tests call the compiled witness calculator directly, bypassing token preflight,
and reject invalid RSA bounds, malformed signed payloads, duplicate/nested/escaped
claims, altered lengths/offsets, and nonce/key/expiry rebinding. A valid witness
has also passed `snarkjs wtns check` against the complete R1CS. These tests are
not an under-constraint audit or a security approval.

The circuit enforces the token's SHA-256 padding itself, the exact 2048-bit
modulus and signature ranges, canonical payload base64url, required top-level
claims, issuer normalization, salt/identity hashing, and signature/message nonce
bindings. The SHA-256 input includes the entire signed header and payload.

## Devnet-only setup and proving

Download the power-21 transcript linked by the
[snarkjs setup guide](https://github.com/iden3/snarkjs#7-prepare-phase-2) and verify
its published BLAKE2b checksum before setup:

```bash
wget https://circom.info/powersOfTau28_hez_final_21.ptau
echo '9aef0573cef4ded9c4a75f148709056bf989f80dad96876aadeb6f1c6d062391f07a394a9e756d16f7eb233198d5b69407cca44594c763ab4a5b67ae73254678  powersOfTau28_hez_final_21.ptau' | b2sum --check
node --max-old-space-size=32768 setup.mjs setup build powersOfTau28_hez_final_21.ptau
node --max-old-space-size=32768 setup.mjs verify build powersOfTau28_hez_final_21.ptau
node --max-old-space-size=32768 setup.mjs prove build
```

Setup adds a fresh random single-contributor contribution without putting its
entropy in command arguments or logs, and exports `vk.json` and the node's
576-byte `vk.bin`. It is not the public production ceremony. `prove` signs a
synthetic token, calculates the full witness, produces an actual 256-byte proof,
verifies it locally, and saves `fixture-proof.json`. Never publish real provider
tokens or private witness files. Large artifacts belong in `build`, not git.

## Run the node and full cryptographic flow

From the repository root:

```bash
RUSTFLAGS=-Znext-solver=coherence CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 \
  cargo +nightly-2026-10-02 build -p tempo --bin tempo --no-default-features --features oidc-devnet
TEMPO_OIDC_DEVNET_VK="$PWD/examples/oidc/build/vk.bin" \
  ./target/debug/tempo node --dev --dev.block-time 1s \
  --http --http.addr 127.0.0.1 --http.port 8545 --http.api eth,net,web3
```

In the example directory:

```bash
node e2e.mjs build/fixture-proof.json http://127.0.0.1:8545
```

The script refuses non-loopback endpoints and any chain other than 1337. It uses
publicly known Anvil development keys, creates a fresh publisher, publishes the
fixture's RSA key, funds the derived OIDC account, mines a proof-authorized payment
with device-key installation, then mines a keychain payment without another proof.
It checks the balance and rejects replay, proof rebinding, invalid proofs, revoked
device keys, and revoked issuer keys. It is a synthetic-provider test, not proof
that Google sign-in works. Proof expiry means a stale fixture must be regenerated.

## Google browser demo

Register a Google web client with authorized JavaScript origin
`http://127.0.0.1:8080`; no client secret is needed for Google Identity Services.
The audience is that client ID. See Google's
[nonce API](https://developers.google.com/identity/gsi/web/reference/js-reference#nonce)
and [client setup](https://developers.google.com/identity/gsi/web/guides/get-google-api-clientid).

Create a durable, randomly generated salt secret of at least 32 bytes in a
private secret file. Do not regenerate it at restart: changing it changes every
user's address. Keep it, provider tokens, and witnesses out of logs and git.
The demo refuses to start without the secret and configured trusted publisher.

```bash
OIDC_CLIENT_ID='<registered-web-client-id>' \
OIDC_PUBLISHER_ID='<trusted-publisher-id>' \
OIDC_SALT_FILE='<durable-private-secret-file>' \
OIDC_ARTIFACTS="$PWD/build" node relay.mjs
```

The relay uses Google's pinned discovery document and JWKS endpoint, verifies
the RSA signature, issuer, audience, and one-use nonce challenge before proving,
and derives the stable HMAC salt from the verified identity. It binds to loopback,
requires exact Host and same-origin JSON requests, limits request sizes and
challenge capacity, and serializes proving. Tokens and witness values are not
returned in errors. This is not a multi-tenant production service.

Publish Google's current keys under the trusted publisher before paying.
`publisher.mjs` converts an already trusted JWKS file into a deduplicated,
sorted `setKeys` transaction plan; it never broadcasts or clears an empty set.
The relay refreshes Google's keys before each token validation, but key publication
is a separate reviewed owner transaction, not an automatic wallet operation.

Open `http://127.0.0.1:8080`, generate the device key in the browser, and sign in
using Google's button. Fund the derived account with test pathUSD, then install
and pay. Subsequent payments use the browser's device key, which never leaves the
tab. Reloading loses it. The relay's RPC proxy only exposes a small method allowlist
and checks private chain 1337 before forwarding; no node admin methods are exposed.

The browser surface and synthetic cryptographic flow have been checked; actual
Google consent is unverified until a registered client ID and user sign-in are
available. Real tokens may exceed TIP-1133's size/format bounds; this must be
checked with the intended provider/client before claiming interoperability.

Offchain Poseidon uses JavaScript BigInt and is not constant-time. Shared vectors
and negative tests do not replace the production audits or ceremony.
