# Zone runtime contracts

This directory contains the Solidity contracts that remain deployed: the shared Tempo Zone
runtimes (`ZonePortal`, `ZoneMessenger`, and `Verifier`) and the `SwapAndDepositRouter` utility.
The shared runtime bytecode is synchronized into the Tempo repository by the
`sync-tempo-zone-runtimes` workflow.

Rust ABI bindings are declared in `tempo-contracts::zones`. The `tempo-zone-contracts` crate
re-exports them and forwards `std`, `serde`, and `rpc`, so Tempo and Zone callers share the same
types and protocol constants. Add or update shared bindings there.

Run the contract tests with a Tempo-capable Foundry build:

```bash
forge test
```
