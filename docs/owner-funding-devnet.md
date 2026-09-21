# Owner funding on a devnet

Node developers can enable signed `requireFunds` transactions on a custom devnet. Add `ownerFunding` to the genesis `config` and activate T12. Existing network configurations omit this field and continue to reject funding transactions.

```json
{
  "config": {
    "t12Time": 0,
    "ownerFunding": {
      "funder": "0xffffffffffffffffffffffffffffffffffff1120",
      "nativeDexSource": "0x0000000000000000000000000000000000001121",
      "parityAssets": [
        "0x20c0000000000000000000000000000000000000",
        "0x20c0000000000000000000000000000000000001",
        "0x20c0000000000000000000000000000000000002"
      ]
    }
  }
}
```

Merge these fields into a complete devnet genesis with its existing fork schedule and allocations. All nodes must use the same configuration. The example addresses are development choices, not assigned production precompile addresses. Funder and source addresses must be distinct, nonzero, and outside existing precompile addresses.

`parityAssets` explicitly approves the native source's input, output, and intermediate route tokens as 1:1 assets. Each asset must be an initialized, unpaused TIP-20 token when used. Configure liquidity separately; the genesis funding configuration neither creates tokens nor places orders.

Sign the full funding array with the owner key. Access key funding remains disabled, including requirements whose balances are already satisfied. The native source's `data` is ABI `(address assetIn, uint256 maxAmountIn)`; use `uint256.max` for an uncapped caller request. The protocol still applies the aggregate shortfall budget.

Funding runs before application calls under the same rollback checkpoint. A funding or application failure reverts swaps, token movements, and funding events. Fees and nonces follow normal transaction behavior. Fees require existing funds or a sponsor. Application calls must remain nonempty under the existing transaction rules.

The signed funding extension, including its optional key-authorization placeholder, pays normal calldata intrinsic and floor gas. Native reads, writes, source calls, and swaps also consume transaction gas. Funded transactions use the general gas lane and are excluded from payment replay optimizations. Pool address filters also check funding source addresses.

Run the signed RPC tests with:

```sh
cargo test -p tempo-node --test it funding::
```

The tests cover a two-input DEX payment, sponsorship, simulation, estimation, tracing, repeated requirements, failure rollback, consecutive transactions, access key rejection, and rejection without configuration or before T12. Two independent nodes execute identical signed funding bytes and compare gas and balances. Production activation and delegated funding are separate work.
