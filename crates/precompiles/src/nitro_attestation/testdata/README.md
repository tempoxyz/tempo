# Nitro attestation fixtures

`aws_attestation_2026_01_03.b64` is the repaired January 2026 production AWS Nitro
attestation published by Base's MIT-licensed `nitro-validator` test suite. It is
untagged COSE_Sign1 with an indefinite-length payload map, 16 PCRs, and a four-certificate
CA bundle. The frozen verification time is `1767472867` (2026-01-03T20:41:07Z).

Upstream: https://github.com/base/nitro-validator/blob/main/test/hinted/HintedNitroAttestation.t.sol

The upstream fixture was missing three bytes in the `public_key` field name while its
CBOR lengths still described the complete payload. The companion upstream helper restores
those bytes before verification:
https://github.com/base/nitro-validator/blob/main/tools/nitro_attestation_input.js
