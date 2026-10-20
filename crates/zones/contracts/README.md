# Zone runtime contracts

This directory contains the Solidity contracts that remain deployed: the shared Tempo Zone
runtimes (`ZonePortal`, `ZoneMessenger`, and `Verifier`) and the `SwapAndDepositRouter` utility.
When changing a shared runtime contract, include its updated deployed bytecode in
[`crates/contracts/src/zones.rs`](../../contracts/src/zones.rs) in the same pull request.
Add hardfork-specific runtime constants and wire them into the factory state in
[`crates/contracts/src/precompiles/zone_factory.rs`](../../contracts/src/precompiles/zone_factory.rs)
and the hardfork-gated installation in [`crates/evm/src/block.rs`](../../evm/src/block.rs).
The new bytecode must only activate at the intended hardfork; preserve the bytecode used by
earlier hardforks.

Run the contract tests with a Tempo-capable Foundry build:

```bash
forge test
```
