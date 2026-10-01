---
tempo-contracts: minor
tempo-precompiles: minor
tempo-evm: minor
---

Record every active zone verifier PCR policy entry in the verifier's storage from T13. The block executor appends newly active entries through a `syncPcrHistory` system call and rejects the block if recorded entries differ from the binary's policy. New views `pcrHistoryLength` and `pcrHistory` expose the recorded history.
