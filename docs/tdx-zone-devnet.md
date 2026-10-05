# Experimental TDX Zone settlement

Build Tempo with `cargo build --release -p tempo --features custom-tdx`.
The native Zone verifier accepts experimental config `0x03` only when every validator
starts with `--zone-verifier.tdx-policy /path/policy.json` and the same
`--zone-verifier.tdx-activation T13` (or a later fork present in its genesis).
The feature and startup policy are both required. Mainnet and Moderato reject
custom activation. No public-network activation or production measurement is included.
The policy schema is the Zones transport JSON: `backend: "tdx"` and an exact
measurement tuple allowlist (MRTD, config/owner/owner-config, all four RTMRs,
TD attributes and XFAM). Debug or zero MRTD policies are rejected.

## Evidence profile

Proof bytes are `TZTDXB01` (8 ASCII bytes), quote length (big-endian u32),
collateral JSON length (big-endian u32), raw quote, collateral JSON.
Quotes are restricted to Intel-vendor ECDSA P-256 TDX quote v4, maximum 64 KiB,
with QE report certification type 6 and an embedded PCK chain (type 5).
All declared outer/nested lengths must match exactly; trailing bytes are rejected.
Collateral is dcap-qvl 0.6.5's `QuoteCollateralV3` JSON, maximum 128 KiB.
Certificate chains are bounded to four entries each; JSON TCB-level lists and
individual collateral fields have additional bounds in the verifier.

Verification uses pinned dcap-qvl 0.6.5, explicitly selects RustCrypto, and checks
Intel's production root, certificate/CRL signatures and revocations, QE identity,
platform/module TCB and all collateral validity windows at **L1 block time**.
Only UpToDate TCB status is accepted. Debug and service TDs are rejected.
SMT, dynamic-platform and cached-key flags are allowed; they are not additional
measurement-policy criteria in this experimental profile.
There are no consensus HTTP requests, host clocks, native DCAP libraries or
externally mutable caches. Off-chain clients collect collateral from Intel PCS.

Report data is the existing NitroBatchAttestation EIP-712 struct digest in bytes
0–31 and zero in bytes 32–63, with `verifierConfigHash = keccak256(0x03)`.
The digest uses the execution-context chain ID and canonical verifier address.
The caller must be the canonical Zone portal. Quotes bind all batch transitions,
height, withdrawal queue, anchor and the separate backend config hash.

Calldata is bounded before ABI decoding and its existing input gas is charged.
An enabled TDX call charges 50,000 parse gas and 3,000,000 verification gas before
cryptographic work. This is a provisional development schedule, not a ratified TIP
or a production gas benchmark. Invalid evidence returns false; gas exhaustion
propagates through the precompile's normal error path.

## Comment-triggered devnets

Tempo has `/build-devnet` on PR comments, including draft PRs from members.
At the inspected revisions, its publisher sends only `name`, `branch`, and
`requested_by`; dev-infra's build-devnet sensor additionally requires `sha` and
`pr_number`. This mismatch must be fixed before treating a comment as a successful
launch. The existing image builds enable custom-pcrs but not custom-tdx, and the
existing workflow does not provision a GCP TDX guest or select a paired Zones SHA.
This verifier change does not alter that deployment machinery.

## Validation limits

Tests use real Intel-signed upstream evidence at a fixed historical timestamp,
including binding, measurement, expiration and tampering failures. Those fixture
measurements are not software approval. Live GCP TDX, an immutable measured prover
image, and complete Zone-to-L1 TDX settlement still require hardware/integration
validation. On an isolated laboratory devnet, observed mutable-guest measurements
may be used only with synthetic witnesses and explicit development trust.
