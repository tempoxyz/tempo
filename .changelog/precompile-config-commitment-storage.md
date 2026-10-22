---
tempo-precompiles: minor
---

Added account config-commitment reads and writes to precompile storage (`PrecompileStorageProvider::{config_commitment, set_config_commitment}`, `StorageCtx`, `ConfigCommitmentWriteGas`) with the TIP-1108 write charges and `TempoPrecompileError::InvalidConfigCommitmentWrite`. Only the in-memory test provider stores commitments; nothing calls them yet.
