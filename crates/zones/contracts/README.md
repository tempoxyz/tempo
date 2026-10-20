# Zone runtime contracts

This directory contains the Solidity contracts that remain deployed: the shared Tempo Zone
runtimes (`ZonePortal`, `ZoneMessenger`, and `Verifier`) and the `SwapAndDepositRouter` utility.
When changing a shared runtime contract, update its bytecode in the same pull request.

Run the contract tests with a Tempo-capable Foundry build:

```bash
forge test
```
