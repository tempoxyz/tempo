# OIDC RS256 v1 circuit

Reference circom circuit for [TIP-1133](../../tips/tip-1133.md), scheme `0x01` of [TIP-1131](../../tips/tip-1131.md) ZK signatures. It proves that an RS256-signed OpenID Connect ID token identifies a user and commits to an access key or a message. Its only public signal is `public_input`.

| Path | Contents |
|---|---|
| `circuits/` | `OidcRs256` and its gadgets: SHA-256 with in-circuit padding, RSA-2048, base64url, the JSON lexer, and member extraction |
| `src/` | TIP-1133 hashing and the input builder, in TypeScript |
| `test/` | Gadget tests, JSON differential tests, and full-circuit tests for every TIP-1133 test case |
| `scripts/` | Development setup and the test vectors `tempo-zk` verifies |

## Requirements

- Node.js 22.18 or later
- [circom](https://github.com/iden3/circom) 2.2.3 on `PATH`, or set `CIRCOM`

## Usage

```sh
npm ci
npm test            # compiles test circuits into build/ and runs every suite
npm run typecheck
npm run build       # build/main/main.r1cs and main_js/main.wasm, with --O2
```

The compiled circuit has 801,008 constraints, so a `2^20` Powers of Tau transcript fits it.

## Development keys

`setup:dev` runs a Groth16 setup with one random contribution and a fixed beacon. Its keys are for tests only; TIP-1133 defines the production ceremony. The `dev` chainspec (`crates/chainspec/src/genesis/dev.json`) carries the current development verifying key in `zkVerifyingKeys`, so a `--chain dev` node accepts proofs made with the matching proving key.

```sh
curl -o build/ppot_0080_20.ptau \
  https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_20.ptau
npm run setup:dev   # build/dev/oidc_rs256.zkey and verification_key.json
npm run vectors     # proves a test token in both forms for the tempo-zk and tempo-revm tests
```

## Implementation choices

TIP-1133 leaves limb sizes and hint encodings to the implementation.

- RSA values use 17 limbs of 121 bits, least significant first. The prover supplies the quotients of the 16 squarings and the final multiplication, and the 16 intermediate remainders; the final remainder is the encoded digest.
- The circuit derives each member's offset from its unique match, so offsets are not inputs. The prover supplies the lengths of the `iss`, `aud`, and `sub` values and the digit counts of `iat` and `exp`, each forced by the bytes that follow.
- `issuer`, `key_hash`, `address_seed`, and `issued_at` are computed in the circuit rather than taken as inputs.
