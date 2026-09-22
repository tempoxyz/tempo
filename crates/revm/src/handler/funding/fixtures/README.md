# Funding callback fixture

`FundingSource.sol` tests transaction-handler callbacks using standard EVM frames through compiled Solidity. It records callback arguments and provides failure modes for static writes, malformed quotes, reverts, out-of-gas, nested rollback, and calls to the inactive protocol sender address. An application call checks that funding occurred before reverting, proving shared rollback.

Regenerate `FundingSource.hex` with Solidity 0.8.30, optimization enabled, and Cancun bytecode:

```sh
solc --optimize --evm-version cancun --bin-runtime FundingSource.sol
```

Save the runtime hex printed after `Binary of the runtime part:` in `FundingSource.hex`. Rust tests load this artifact directly and do not require a Solidity compiler.

The test-only protocol caller address is `0xffffffffffffffffffffffffffffffffffff1120`. Input-debit modes exercise native bounded permissions, nested rollback, and refunds. Output delivery checks remain outside this fixture. Production builds do not register a funding entry point.

`OwnerFundingSource.sol` also exercises delegated execution: its policy data encodes the allowed input token. Regenerate its checked-in runtime with:

```sh
forge inspect --root crates/revm/src/handler/funding/fixtures --contracts . --use 0.8.30 --optimize --optimizer-runs 200 --evm-version cancun OwnerFundingSource deployedBytecode > /tmp/OwnerFundingSource.hex
cp /tmp/OwnerFundingSource.hex crates/revm/src/handler/funding/fixtures/OwnerFundingSource.hex
```
