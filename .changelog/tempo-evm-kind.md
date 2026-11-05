---
tempo-primitives: minor
tempo-precompiles: minor
tempo-evm: minor
zone-evm: patch
zone-precompiles: patch
---

Added `TempoEvmKind`, the kind of Tempo EVM (L1 or zone), which fixes the protocol rules that differ between Tempo and its zones. `TempoEvmExt::new(evm_kind, fee_manager)` replaces `TempoEvmExt::with_fee_manager`, and `PrecompileStorageProvider::evm_kind` replaces `set_revert_blocked_inbound` and `revert_blocked_inbound`. Blocked TIP-1028 inbounds now revert in every storage context over a zone EVM, not only inside zone precompile calls from T15; before T15 no zone path could reach a blocked inbound, so historical execution is unchanged. `TIP20Token::mint_with_role` is removed: TIP-20 mints on zones authorize recipients with TIP-403 `Recipient` from T13 on their own.
