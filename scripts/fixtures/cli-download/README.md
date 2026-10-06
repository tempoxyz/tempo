# CLI snapshot download fixtures

These synthetic Moderato archives exercise snapshot installation, not node
bootability. Each archive contains one 27-byte text file. The tar entries have
zero timestamps and are compressed with Zstandard, then base64-encoded so the
fixtures remain reviewable text. The manifest records compressed sizes and
BLAKE3 checksums for both archives and their extracted files.

`scripts/test-cli.sh` decodes the fixtures using `base64`, loads the manifest via
`--manifest-url file://...`, and verifies execution files, consensus files, and
generated configuration with and without `--chain moderato`. No HTTP server,
Python, compression tool, or checksum tool is needed to run the test. HTTP
transport is not covered.
