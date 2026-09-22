# Funding discovery

`FundingDiscovery` is a read-only Solidity helper. Deploy it with the native `FundingPolicy` address, then call `discover(policyId, account, token, amount)` before constructing a transaction. It does not require a reserved address or protocol activation.

The helper reads `getPolicy`, checks the requested token, and queries every source using the same shortfall and aggregate budget. It preserves candidate order, propagates failures, and rejects malformed candidates. Results are independent estimates, not reserved or additive balances.

Copy candidate `target` and `data` into `requireFunds[].sources`. Execution must still enforce current policy rules, key permissions, available funds, and slippage.

The Solidity interfaces are authoritative. Rust bindings consume their generated JSON ABIs. Regenerate artifacts from the repository root:

```sh
forge inspect --root crates/contracts/solidity IFundingPolicy abi --json > crates/contracts/abi/IFundingPolicy.json
forge inspect --root crates/contracts/solidity IFundingDiscovery abi --json > crates/contracts/abi/IFundingDiscovery.json
forge inspect --root crates/contracts/solidity FundingDiscovery bytecode > crates/revm/src/handler/funding/fixtures/FundingDiscovery.hex
forge inspect --root crates/contracts/solidity Source bytecode > crates/revm/src/handler/funding/fixtures/DiscoverySource.hex
```

`Source` is the test fixture in `test/FundingDiscovery.t.sol`. Rust integration tests deploy the helper and fixture bytecode and exercise real native policy storage and TIP-20 balances.

Run the helper tests and formatting check:

```sh
forge test --root crates/contracts/solidity
forge fmt --root crates/contracts/solidity --check
```
