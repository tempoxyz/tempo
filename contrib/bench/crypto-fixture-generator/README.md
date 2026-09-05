# Ordinary Ethereum precompile fixtures

This isolated helper produces deterministic inputs/expected outputs for all 18
addresses in `revm-precompile` 42.0.1's Osaka registry. It does not send
transactions, benchmark timing, or change the node's dependencies or gas schedule.

Run from the Tempo repository root:

```sh
cargo run --manifest-path contrib/bench/crypto-fixture-generator/Cargo.toml --locked
cargo +nightly fmt --manifest-path contrib/bench/crypto-fixture-generator/Cargo.toml --check
cargo +nightly clippy --manifest-path contrib/bench/crypto-fixture-generator/Cargo.toml --all-targets --locked -- -D warnings
```

The JSON belongs in `contrib/bench/txgen/gas-calibration/ethereum-fixtures.json`;
`ethereum-presets.py` then emits the individual preset YAML and the smoke mix.
The checked-in lockfile pins the helper independently of the production workspace.
Re-generating the same fixture version must produce byte-identical JSON.

Inputs are bounded to 1,024 bytes. BLS MSMs have one term, pairing checks have two
nonzero cancellation pairs, BLAKE2b uses its standard twelve-round `abc` input,
and MODEXP uses a 2,048-bit odd modulus with exponent 65,537. The modulus is not
represented as a generated RSA key. No extended-round or oversized-input cases
are included. Signing keys are public fixed test constants, never wallet keys.

EC arithmetic, signatures and MODEXP have separately constructed expected results.
KZG and BLAKE2b reuse source-attributed ordinary fixtures. BLS map outputs are
checked for nonzero, on-curve and subgroup membership with arkworks, but do not
have an independent exact-map oracle. Hash outputs are checked for pinned-library
consistency; independent hash fixtures also exist in `GasCalibration`.

Every row is executed by the pinned library and checked for success and the
expected result, then the address set is compared with the complete Osaka registry.
The reported `operation_gas` is a library gas charge, not transaction gas or a
measured execution time. The helper's crypto backend/features need not match the
benchmark node; no performance inference may be drawn from running this helper.

These single fixture points are not full input-distribution coverage or pricing
evidence. Multiple ordinary inputs/sizes, runtime constructor checks, validated
receipts, matched repeated timing runs and opcode controls remain necessary.

## Additional mainnet-sized inputs

Passing `-- --mainnet-sizes` emits a separate three-row set for
`mainnet-size-fixtures.json`: SHA-256 with 448 bytes, MODEXP with three 32-byte
operands, and BN254 pairing with four nonzero pairs. `ethereum-presets.py
--mainnet-sizes` emits those individual presets and their separate three-way
smoke. The default 18-row output is unchanged.

The dimensions were observed in read-only `TEMPO_CHAIN.STAGING.STG_TRACES`
aggregates over September 4, 2026 07:00 UTC through September 5 07:00 UTC
(exclusive): 23 SHA calls with median/maximum 448 bytes, nine MODEXP calls with
32-byte length fields, and 20 pairing calls with 768-byte inputs. Inputs here
are newly generated and valid, not copies of observed transactions; they do not
establish the original operand distribution. SHA has an independent hashlib
expected value, MODEXP uses num-bigint, and pairing uses cancellation identities.
These cases remain below the same 1,024-byte input bound.

## Native signature fixtures

Passing `-- --native-signatures` emits eight separate `SignatureVerifier`
fixtures: recover/verify for secp256k1, P256 raw, P256 SHA-256 prehash, and an
ordinary WebAuthn assertion. They use fixed public test keys, a 37-byte
authenticator record without extensions, and `https://bench.example` as a test
origin. They are not browser-authentication tests or real-user credentials.

Store the output as `native-signature-fixtures.json`, then generate presets with
`ethereum-presets.py --native-signatures`. The helper verifies the signatures
locally; its native `source_crypto_gas` field is the source's crypto component,
not measured total native gas. It does not execute native dispatch locally.
The wrapper constructor must still validate every expected native return value
on the pinned benchmark node before the workload starts.

Independent ABI, challenge, hashing, ECDSA and signer checks use a Python backend:

```sh
uv run --with cryptography==50.0.0 --with pycryptodome==3.23.0 python contrib/bench/txgen/gas-calibration/validate-native-signatures.py
uv run --with cryptography==50.0.0 --with pycryptodome==3.23.0 python -m unittest discover -s contrib/bench/txgen/gas-calibration -p test_native_signature_fixtures.py
```

The independent checker does not replace native runtime checks. Keychain/admin
authorization, full transaction authentication and varied WebAuthn client data
remain separate coverage obligations. Existing inherited-precompile and size
fixture outputs are unchanged by this mode.
