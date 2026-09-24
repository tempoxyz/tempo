# Funding discovery

Call `FundingDiscovery.discover(account, token, amount, rules)` at `0x1120000000000000000000000000000000000003` to discover using supplied rules without a stored policy. `rules` is the canonical ABI encoding of `IFundingPolicy.Rules`.

The overload `discover(policyId, account, token, amount, rules)` also verifies the rules against the stored policy commitment. Both use ordinary EVM static calls to query sources in rule order with the same shortfall and aggregate cost budget. Neither grants spending authority.

Copy candidate `target` and `data` into `requireFunds[].sources`. Candidates are independent estimates, not reserved funds. Access key execution still requires `policyRules` matching its stored policy. Execution validates applicable key permissions, available funds, and slippage.

The node installs the compiled Solidity runtime at T13. Ordinary EVM execution handles source calls; no custom discovery frames are required. Regenerate artifacts from the repository root:

```sh
forge inspect --root crates/contracts/solidity IFundingPolicy abi --json > crates/contracts/abi/IFundingPolicy.json
forge inspect --root crates/contracts/solidity IFundingDiscovery abi --json > crates/contracts/abi/IFundingDiscovery.json
forge inspect --root crates/contracts/solidity FundingDiscovery deployedBytecode
forge inspect --root crates/contracts/solidity Source bytecode > crates/revm/src/handler/funding/fixtures/DiscoverySource.hex
forge inspect --root crates/contracts/solidity DiscoveryCaller bytecode > crates/revm/src/handler/funding/fixtures/DiscoveryCaller.hex
forge inspect --root crates/contracts/solidity RecursiveSource bytecode > crates/revm/src/handler/funding/fixtures/RecursiveDiscoverySource.hex
```

Copy the deployed bytecode into `FUNDING_DISCOVERY_RUNTIME` in `crates/contracts/src/funding_discovery.rs`. The compiler settings in `foundry.toml` pin Solidity 0.8.30, Osaka, via-IR compilation, and 200 optimizer runs. The contract has no constructor arguments or storage initialization.

The contracts in `test/FundingDiscovery.t.sol` are fixtures for Rust EVM integration tests, which exercise protocol-deployed discovery, policy storage, and TIP-20 balances.

```sh
forge test --root crates/contracts/solidity
cargo test -p tempo-revm discovery --lib
forge fmt --root crates/contracts/solidity --check
```
