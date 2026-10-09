---
tempo-chainspec: minor
---

Add the `zkVerifyingKeys` genesis field (`TempoGenesisInfo::zk_verifying_keys`), which sets verifying keys for ZK signature schemes that have no protocol key yet. The `dev` chainspec sets the development key of the TIP-1133 OIDC RS256 v1 circuit, so `--chain dev` accepts its proofs.
