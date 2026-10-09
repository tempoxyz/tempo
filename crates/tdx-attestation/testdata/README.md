Fixtures copied from Phala-Network/dcap-qvl v0.6.5 (MIT), commit
884e22ce767f31fd5d5a6672511519fc7975cde0, sample/tdx_quote and
sample/tdx_quote_collateral.json. They contain real Intel-signed evidence from
2025, not Tempo-approved software or a Tempo batch commitment. Tests verify at
2025-06-20T00:00:00Z; never use these measurements as deployment approval.

The quote fixture omits the source file’s 70 zero padding bytes after the declared
signature payload. Signed bytes are unchanged; this profile rejects trailing data.
