# `tempo-alloy` Examples

Runnable examples demonstrating common operations with the `tempo-alloy` crate.

## Prerequisites

Set the `RPC_URL` environment variable to a Tempo RPC endpoint:

```bash
export RPC_URL="https://rpc.testnet.tempo.xyz"
```

## Running Examples

Run any example with:

```bash
cargo run --example <example_name> -p tempo-alloy
```

## Examples

| Example | Description |
|---------|-------------|
| `get_balance` | Get the balance of a token for an address |
| `get_block_number` | Get the current block number from the network |
| `configure_provider` | Configure a Tempo provider to interact with the network |
| `transfer` | Send a basic token transfer |
| `transfer_with_memo` | Send a token transfer with a memo for payment reconciliation |
| `batch_payments` | Send multiple payments in a single batch transaction |
| `watch_transfers` | Watch for incoming transfer events on a token |
| `watch_transfers_with_memo` | Watch for incoming transfers with memo for payment reconciliation |
| `mint_tokens` | Mint stablecoins to a recipient address |
| `burn_tokens` | Burn stablecoins from your own balance |
| `mint_fee_liquidity` | Add liquidity to a fee pool to enable fee payments with your token |
