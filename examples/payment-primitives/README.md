# Tempo Payment Primitives

Innovative payment primitive contracts for the Tempo Network, leveraging TIP-20 tokens and Tempo's unique memo-based reconciliation features.

## Contracts

### TempoPaymentSplitter

A contract for splitting TIP-20 token payments to multiple recipients in a single transaction.

**Features:**
- Create payment splits with multiple payees and custom share percentages
- Add/remove payees dynamically with share rebalancing
- Distribute TIP-20 tokens proportionally to all payees in one transaction
- Batch payments to multiple recipients
- Memo support for invoice/reference tracking (leveraging Tempo Transaction memos)
- Up to 50 payees per split configuration

**Use Cases:**
- Revenue sharing among team members or partners
- Automated royalty distribution
- Multi-vendor payment settlement
- DAO treasury distributions

### TempoStreamingPayments

A Sablier-style continuous payment streaming contract optimized for TIP-20 tokens on Tempo.

**Features:**
- Create continuous payment streams with custom start/end times
- Batch stream creation for multiple recipients
- Real-time balance calculation based on elapsed time
- Withdraw accumulated funds at any time
- Cancel streams with proportional refunds to sender
- Top up existing streams to extend funding
- Memo support for payment tracking

**Use Cases:**
- Employee salary streaming
- Contractor payment schedules
- Token vesting with real-time claims
- Subscription-based services
- Milestone-based project funding

## Deployment

Both contracts are deployed and verified on Tempo Moderato Testnet (Chain ID: 42431):

| Contract | Address |
|----------|---------|
| TempoPaymentSplitter | `0xB0c73Af547dB09F817202e4B2d30Dae6478C7D26` |
| TempoStreamingPayments | `0xd616458d15c9BDf2972A59b79E8168023c5f77ad` |

## Building

```bash
forge build
```

## Testing

```bash
forge test
```

## Token

These contracts work with PathUSD (TIP-20) at `0x20C0000000000000000000000000000000000000` on Moderato testnet.

## License

MIT
