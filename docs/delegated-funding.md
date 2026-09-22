# Delegated funding

At T13, an access key can use `requireFunds` when its signed authorization includes `fundingPolicy`. Keys without a binding cannot fund, even when the requested balance is already present. Funding does not replace the key's application-call permissions.

## Policy and key installation

`FUNDING_POLICY_ADDRESS` is `0x1120000000000000000000000000000000000002`. The node installs its marker bytecode at T13 using the existing precompile activation path. This draft address remains subject to protocol review.

The owner signs either a nonzero existing policy ID or an inline policy. An inline policy contains `admins`, `slippageBps`, and token-indexed `sources`; its canonical wire form contains routes sorted by token address. Source order within a route is significant.

Policy creation and key binding share the key-installation checkpoint. An invalid policy cannot leave a key installed. Installation precedes the application checkpoint, so a later funding or payment failure preserves the key and policy, as existing key installation does.

Read the ID through `IAccountKeychain.getFundingPolicyId(account, keyId)` or the inline installation's `PolicyCreated` event. Zero means no funding permission. Replaying an installed key authorization fails without allocating another policy; subsequent transactions omit the authorization.

## Execution

The handler snapshots the bound policy before funding. Each requirement must name an allowed output token. All supplied sources must belong to that route in nondecreasing order, including sources that would be skipped once the balance is satisfied. Sources may repeat or be omitted.

Omitted transaction slippage uses the policy tolerance. An explicit value must equal it. Each requirement has one aggregate budget based on its initial shortfall. The handler passes each source's policy data to `quote`, then grants temporary authority for the quoted input during `fund`.

The key's output-token limit pays the shortfall. Input debits use the bounded native permission instead of input-token limits or allowances. Key validity, token policies, delivery checks, gross input caps, and rollback remain enforced.

## Credit accounting

Measured delivery creates transient credit scoped to the account, key, and output token. A subsequent transfer uses that credit before charging the remaining amount to the key. The spending check still validates the key when credit covers the whole amount.

Approval increases move covered credit into a separate spender-bound balance. Allowance spending retires that balance before free funding credit. Old allowances retire free credit; decreases never restore it. Approval credit for the zero address is separate from free credit.

Burns and bounded input debits also retire free credit. Fees always charge ordinary spending limits. Incoming transfers and refunds never create credit. Native transient storage provides nested rollback and clears credits after the transaction.

## Discovery

Deploy the read-only [FundingDiscovery helper](../crates/contracts/solidity/README.md) with the policy address. It returns ordered source candidates through ordinary static calls. Candidates are estimates, not reserved funds; execution obtains fresh quotes and validates the current policy.

## Verification

```sh
cargo test -p tempo-precompiles --features test-utils --lib
cargo test -p tempo-revm --lib
cargo test -p tempo-node --test it funding::
cargo test -p tempo-e2e owner_funding_finalization_and_gas -- --nocapture
forge test --root crates/contracts/solidity
```

The network fixture includes inline installation, policy reuse, a second key using an existing policy, exhausted limits, and payment failure after funding. Four validators compare finalized blocks, state roots, receipts, balances, and policy bindings. `FUNDING_GAS_RESULTS` reports creation and reuse costs alongside owner funding.

Earn vault adapters remain external contracts. Production activation still requires protocol review of the addresses, gas schedule, and T13 deployment schedule, plus green CI on the final stack.

## Measured gas

Measured on the T13 four-validator fixture with Rust 1.95.0. Each successful payment sources 50 pathUSD from two inputs, using up to 30 units of the first. These totals include transaction overhead, key installation when applicable, funding, and payment.

| Scenario | Total gas |
| --- | ---: |
| Inline policy, new key, and payment | 8,387,914 |
| Existing policy ID, new key, and payment | 3,107,114 |
| Reuse installed key and policy | 350,530 |
| Reject exhausted output limit | 90,355 |
| Fund, then revert payment | 586,087 |

Creation includes storage charges for the policy and key restrictions. Scenarios execute sequentially against changing books and storage, so these values are reproducible fixture results rather than isolated estimates of policy overhead.
