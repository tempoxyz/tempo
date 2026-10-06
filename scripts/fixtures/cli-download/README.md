# CLI snapshot download fixtures

These synthetic archives exercise snapshot installation, not node
bootability. Each archive contains one 27-byte text file. The tar entries have
zero timestamps and are compressed with Zstandard, then base64-encoded so the
fixtures remain reviewable text. The manifest records compressed sizes and
BLAKE3 checksums for both archives and their extracted files.

`scripts/test-cli.sh` decodes the fixtures using `base64`, loads the manifest via
`--manifest-url file://...`, and verifies execution files, consensus files, and
generated configuration for both testnet (`42431`) and mainnet (`4217`), with
and without the matching `--chain` argument. The script substitutes the chain
ID in the manifest while sharing the same chain-independent archives. No HTTP
server, Python, compression tool, or checksum tool is needed to run the test.
HTTP transport is not covered.
