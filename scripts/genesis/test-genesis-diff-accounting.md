# test-genesis.json Diff Accounting (vs main)

## Summary
- **Additions**: 116 lines
- **Removals**: 119 lines
- **Net**: -3 lines (factory storage removed)

## Change Categories

### 1. PathUSD Quote Token Reference (2 changes)
PathUSD (`0x20c0000000000000000000000000000000000000`) now references itself as quote token instead of zero address.

| Slot | Old Value | New Value | Meaning |
|------|-----------|-----------|---------|
| 0x06 | `0x...0000` | `0x...20c0...0000` | quoteToken: zero → PathUSD |
| 0x07 | `0x...01...0000` | `0x...01...20c0...0000` | Packed: paused(1) + quoteToken |

### 2. Token Address Changes (3 tokens)
Token addresses changed from sequential IDs to deterministic addresses based on `keccak256(sender, salt)`.

| Token | Old Address | New Address |
|-------|-------------|-------------|
| Token 1 | `0x20c0...0001` | `0x20c0...a3c1274aadd82e4d12c8` |
| Token 2 | `0x20c0...0002` | `0x20c0...bc40fbf4394cd00f78fa` |
| Token 3 | `0x20c0...0003` | `0x20c0...c651ee22c6951bb8b5bd` |

### 3. TIP20Factory Storage Removed (1 entry → 0)
Factory at `0x20fc000000000000000000000000000000000000` no longer stores `nextTokenId` counter.

| Slot | Old Value | New Value |
|------|-----------|-----------|
| 0x00 | `0x...04` (nextTokenId=4) | (removed) |

### 4. StablecoinExchange Storage (~110 changes)
Exchange at `0xabc1000000000000000000000000000000000000` has storage referencing token addresses.
All references to token 1 changed from `...0001` to `...a3c1274aadd82e4d12c8`.

These are likely:
- **Order book entries**: pairs mapping base token to book data
- **Fee token references**: validator fee token mappings
- **User positions**: order amounts keyed by (user, token)

#### Storage Key Analysis
The storage keys are keccak256 hashes of mappings. Same keys, different values (the token addresses).

Example pattern:
```
OLD: 0x001c4f49... → 0x...20c0...0001
NEW: 0x001c4f49... → 0x...20c0...a3c1274aadd82e4d12c8
```

#### New/Removed Storage Keys
Some storage keys changed because they include the token address in the key computation:

**Removed keys** (old token addresses in key):
- `0x053a2021ba...` (fee amount for old token 1)
- `0x05de1dc1c5...` (balance for old token 1)
- `0x14901df7a9...` (allowance for old token 1)
- `0x791faf927d...` (balance for old token 1)
- `0x2f27f922df...` (total supply for old token 1)
- etc.

**Added keys** (new token addresses in key):
- `0x09410ef02c...` (fee amount for new token 1)
- `0x0f4e726e7b...` (balance for new token 1)
- `0x49ad5c20c9...` (total supply for new token 1)
- etc.

## Verification
The net removal of 3 lines comes entirely from TIP20Factory storage removal:
- OLD: 4 lines (`"code": "0xef",` + `"storage": {` + key-value + `}`)
- NEW: 1 line (`"code": "0xef"`)
- Net: -3 lines

The mapping key changes in StablecoinExchange are 1:1 (same number of entries, just different keys due to new token addresses).

All changes are consistent with the TIP20 address scheme change from sequential IDs to deterministic addresses.
