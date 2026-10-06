# CLI snapshot download fixtures

These synthetic archives exercise snapshot installation, not node
bootability. Each archive contains one 27-byte text file. The tar entries have
zero timestamps and are compressed with Zstandard, then base64-encoded so the
fixtures remain reviewable text. The manifest records compressed sizes and
BLAKE3 checksums for both archives and their extracted files.

`scripts/test-cli.sh` starts a bare-Node HTTPS mock proxy through
`scripts/test-cli-download.mjs`. It exercises testnet (`42431`) and mainnet
(`4217`) discovery without `--manifest-url` or `--manifest-path`, including
omitted `--chain` selecting mainnet. The discovery response contains both
chains, and tests verify that only the expected manifest and archives are
requested. Explicit-source cases with and without `--chain` retain coverage
for the original implicit-chain regression.

The proxy accepts only `CONNECT snapshots.tempoxyz.dev:443`, terminates TLS,
and serves the listing, chain-specific manifests, and archives from fixtures.
It supports HEAD and byte-range requests, records request paths, and rejects
unknown hosts, methods, and paths without forwarding any traffic. Each case
checks installed execution and consensus file contents and generated config.
Child-process timeouts and cleanup keep failures bounded.

Only Node built-ins are used: no npm packages, Python, Hurl, or compression and
checksum tools are needed. Node must be available on the test runner.
`node --test scripts/cli-download-proxy.test.mjs` checks the proxy protocol,
request rejection, ranges, and required CA trust.

`ca.pem`, `server.pem`, and `server.key` are public test fixtures, not production
credentials. The server certificate is valid for `snapshots.tempoxyz.dev` and
expires in 2126. Only the test child process trusts `ca.pem` via `SSL_CERT_FILE`;
the system trust store and production TLS configuration are unchanged.
Inherited proxy variables are removed before setting the local `HTTPS_PROXY`.
