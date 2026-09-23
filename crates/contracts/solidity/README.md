# Funding policy interface

Call `FundingPolicy.discover(policyId, account, token, amount)` at the native policy address before constructing a transaction. Discovery uses ordinary EVM static calls to query sources in policy order with the same shortfall and aggregate cost budget.

Copy candidate `target` and `data` into `requireFunds[].sources`. Candidates are independent estimates, not reserved funds. Execution validates the current policy, key permissions, available funds, and slippage.

The Solidity interface defines the ABI consumed by Rust. Regenerate artifacts from the repository root:

```sh
forge inspect --root crates/contracts/solidity IFundingPolicy abi --json > crates/contracts/abi/IFundingPolicy.json
forge inspect --root crates/contracts/solidity Source bytecode > crates/revm/src/handler/funding/fixtures/DiscoverySource.hex
forge inspect --root crates/contracts/solidity DiscoveryCaller bytecode > crates/revm/src/handler/funding/fixtures/DiscoveryCaller.hex
forge inspect --root crates/contracts/solidity RecursiveSource bytecode > crates/revm/src/handler/funding/fixtures/RecursiveDiscoverySource.hex
forge inspect --root crates/contracts/solidity DiscoveryDelegateCaller bytecode > crates/revm/src/handler/funding/fixtures/DiscoveryDelegateCaller.hex
```

The contracts in `test/FundingDiscovery.t.sol` are fixtures for Rust EVM integration tests, which exercise native discovery, policy storage, and TIP-20 balances.

```sh
cargo test -p tempo-revm discovery --lib
forge fmt --root crates/contracts/solidity --check
```
