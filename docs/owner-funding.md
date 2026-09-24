# Owner funding

Owner-signed `requireFunds` transactions activate at T13. Earlier forks reject them. No funding-specific genesis configuration is needed; local devnets use the existing `t13Time` fork setting.

The protocol defines two fixed addresses in `tempo-contracts`:

| Constant | Address | Purpose |
| --- | --- | --- |
| `TIP20_FUNDER_ADDRESS` | `0x1120000000000000000000000000000000000000` | Protocol funding caller and accounting identity. Solidity cannot initiate funding. |
| `DEX_FUNDING_SOURCE_ADDRESS` | `0x1120000000000000000000000000000000000001` | Native DEX source implementing `supportsToken`, `discover`, `quote`, and `fund`. |

The native source requires initialized, unpaused TIP-20 tokens with matching currency metadata across the input, output, and every intermediate route token. The DEX currently supports USD pairs only. Newly created USD tokens need no funding allowlist entry, but must have a supported route and available liquidity.

Matching currency metadata establishes the protocol's 1:1 reference assumption, not market-price equivalence. Metadata is issuer-declared and does not detect depegs. The aggregate slippage budget measures execution against that reference.

Sign the full funding array with the owner key. Access key funding remains disabled, including requirements whose balances are already satisfied. The native source's `data` is ABI `(address assetIn, uint256 maxAmountIn)`; use `uint256.max` for an uncapped caller request. The protocol still applies the aggregate shortfall budget.

Anyone can call `discover(account, token, amount, maxCost, configData)` with ABI-encoded `address[] inputTokens` as `configData`. Candidates preserve input order and contain nonempty `executionData` and independent `availableAmount` estimates. Discovery grants no authority.

Do not sum estimates: candidates can share liquidity or inputs. Use candidate `executionData` directly as transaction source `data`.

Anyone can call the native source's read-only `quote` to estimate one invocation. It accounts for the requested ceiling, wallet and DEX balances, liquidity, input caps, and cost budget. Quotes grant no spending authority.

`Quote.executionData` is reusable by both `quote` and `fund`; re-quoting preserves the input and tightens its cap. The handler obtains a fresh quote before `fund` and independently verifies actual delivery and cost.

Funding runs before application calls under the same rollback checkpoint. A funding or application failure reverts swaps, token movements, and funding events. Fees and nonces follow normal transaction behavior. Fees require existing funds or a sponsor. Application calls must remain nonempty under the existing transaction rules.

The signed funding extension, including its optional key-authorization placeholder, pays normal calldata intrinsic and floor gas. Native reads, writes, source calls, and swaps also consume transaction gas. Funded transactions use the general gas lane and are excluded from payment replay optimizations. Pool address filters also check funding source addresses.

Run the signed RPC tests with:

```sh
cargo test -p tempo-node --test it funding::
```

The tests cover a two-input DEX payment, sponsorship, simulation, estimation, tracing, repeated requirements, failure rollback, consecutive transactions, access key rejection, and rejection before T13. Two independent nodes execute identical signed funding bytes and compare gas and balances. Production activation and delegated funding are separate work.

See [owner funding qualification](owner-funding-qualification.md) for the four-validator demo, gas measurements, security coverage, and remaining release gates.

Funding Policy discovery is defined in the ABI but remains inactive with policy execution. ABI routes pair one output `token` with ordered sources. SDK token maps encode routes in ascending token-address order.
