# `tempo-spam`

Comprehensive transaction generator for Tempo testnet that covers all major codepaths.

## Purpose

This tool generates diverse transactions matching the operations tested in the Tempo invariant fuzz tests (`tips/ref-impls/test/invariants/`). The goal is to ensure testnet has comprehensive transaction variety so that re-execution tests hit all codepaths, preventing false confidence from homogeneous testnet traffic.

## Covered Codepaths

### TIP20 Token Operations
- `transfer` / `transferWithMemo` - Standard token transfers
- `transferFrom` / `transferFromWithMemo` - Allowance-based transfers
- `approve` - Spending allowances
- `mint` / `mintWithMemo` - Token issuance
- `burn` / `burnWithMemo` - Token destruction
- `distributeReward` - Reward distribution to opted-in holders

### StablecoinDEX Operations
- `place` - Place bid/ask orders
- `placeFlip` - Place flip orders (bid that flips to ask when price crosses)
- `cancel` - Cancel existing orders
- `swapExactAmountIn` - Execute swaps
- `withdraw` - Withdraw from internal DEX balance
- `deposit` - Deposit to internal DEX balance

### FeeAMM Operations
- `mint` - Mint LP tokens to pools
- `burn` - Burn LP tokens and withdraw reserves
- `rebalanceSwap` - Rebalance pool reserves
- `distributeFees` - Distribute collected fees to validators

### Nonce Operations
- `incrementNonce` - Increment 2D nonces with various keys

### TIP20Factory Operations
- `createToken` - Create new TIP20 tokens

### TIP403Registry Operations
- `modifyPolicyBlacklist` - Add/remove addresses from blacklists

## Installation

```bash
cargo install --path bin/tempo-spam --profile maxperf
```

## Usage

### Basic Usage

```bash
# Run with default settings (100 TPS for 60 seconds)
tempo-spam spam --faucet

# Higher throughput
tempo-spam spam --tps 500 --duration 120 --faucet

# Custom RPC endpoint
tempo-spam spam --target-urls http://your-node:8545 --faucet
```

### Command Line Options

```
Usage: tempo-spam spam [OPTIONS]

Options:
  -t, --tps <TPS>                          Target transactions per second [default: 100]
  -d, --duration <DURATION>                Test duration in seconds [default: 60]
  -a, --accounts <ACCOUNTS>                Number of accounts [default: 20]
  -m, --mnemonic <MNEMONIC>                Mnemonic for accounts [default: random]
      --target-urls <TARGET_URLS>          Target RPC URLs [default: http://localhost:8545]
      --faucet                             Fund accounts from faucet before running
      --user-tokens <USER_TOKENS>          Number of test tokens to create [default: 4]
      
Action Weights (higher = more frequent):
      --weight-tip20-transfer <N>          TIP20 transfer weight [default: 20]
      --weight-tip20-transfer-from <N>     TIP20 transferFrom weight [default: 10]
      --weight-tip20-approve <N>           TIP20 approve weight [default: 5]
      --weight-tip20-mint <N>              TIP20 mint weight [default: 5]
      --weight-tip20-burn <N>              TIP20 burn weight [default: 3]
      --weight-tip20-reward <N>            TIP20 reward distribution weight [default: 2]
      --weight-dex-place <N>               DEX place order weight [default: 15]
      --weight-dex-place-flip <N>          DEX place flip order weight [default: 5]
      --weight-dex-cancel <N>              DEX cancel order weight [default: 3]
      --weight-dex-swap <N>                DEX swap weight [default: 10]
      --weight-dex-withdraw <N>            DEX withdraw weight [default: 2]
      --weight-dex-deposit <N>             DEX deposit weight [default: 2]
      --weight-amm-mint <N>                FeeAMM mint weight [default: 5]
      --weight-amm-burn <N>                FeeAMM burn weight [default: 3]
      --weight-amm-rebalance <N>           FeeAMM rebalance swap weight [default: 3]
      --weight-amm-distribute-fees <N>     FeeAMM distribute fees weight [default: 2]
      --weight-nonce-increment <N>         Nonce increment weight [default: 5]
      --weight-token-create <N>            Token creation weight [default: 1]
      --weight-policy-modify <N>           Policy modification weight [default: 2]
```

### Examples

```bash
# Focus on DEX operations
tempo-spam spam --faucet \
  --weight-dex-place 30 \
  --weight-dex-swap 20 \
  --weight-dex-place-flip 10 \
  --weight-tip20-transfer 5

# Focus on token operations
tempo-spam spam --faucet \
  --weight-tip20-transfer 30 \
  --weight-tip20-mint 20 \
  --weight-tip20-burn 15 \
  --weight-tip20-reward 10

# Comprehensive coverage with more accounts
tempo-spam spam --faucet --accounts 50 --tps 200 --duration 300 --user-tokens 8
```

## Relationship to Invariant Tests

The actions in this tool correspond to the handlers in the invariant tests:

| Invariant Test File | Covered Actions |
|---------------------|-----------------|
| `StablecoinDEX.t.sol` | DexPlace, DexPlaceFlip, DexCancel, DexSwap, DexWithdraw, DexDeposit |
| `FeeAMM.t.sol` | AmmMint, AmmBurn, AmmRebalance, AmmDistributeFees |
| `TIP20.t.sol` | Tip20Transfer, Tip20TransferFrom, Tip20Approve, Tip20Mint, Tip20Burn, Tip20DistributeReward |
| `Nonce.t.sol` | NonceIncrement |
| `TIP20Factory.t.sol` | TokenCreate |
| `TIP403Registry.t.sol` | PolicyModify |

## Integration with Re-execution Tests

Run `tempo-spam` against testnet before creating snapshots for re-execution tests:

```bash
# Generate comprehensive traffic on testnet
tempo-spam spam --faucet --tps 100 --duration 600 \
  --target-urls http://testnet-node:8545

# Wait for blocks to finalize, then create snapshot for re-execution tests
```

This ensures that the testnet state includes diverse transactions that exercise all codepaths, making re-execution tests more reliable at catching regressions.
