# Tempo Zones

Zones are L2 chains anchored to Tempo L1. Each zone has its own sequencer, genesis state, and portal contract on L1 that escrows deposits and processes withdrawals.

**Explorers:** [Moderato](https://explore.moderato.tempo.xyz/) · [Devnet](https://explore.devnet.tempo.xyz/)

## Quick Start (One Command)

The fastest way to deploy and run a zone on moderato:

```bash
export L1_RPC_URL="wss://rpc.moderato.tempo.xyz"
just zones::deploy-zone my-zone
```

To choose a different initial TIP-20 on the portal at deploy time, pass it as the second positional argument:

```bash
just zones::deploy-zone my-zone alphausd
```

This single command will:
1. Generate a fresh sequencer keypair
2. Fund the sequencer on L1 via `tempo_fundAddress`
3. Build the Solidity specs
4. Deploy a zone on L1 via ZoneFactory (`createZone`)
5. Generate the zone's `genesis.json` and `zone.json`
6. Build and start the zone node

> `deploy-zone` creates distinct admin and sequencer keys unless `ADMIN_KEY` or `ADMIN_ADDR` supplies the admin. It saves the available keys and both addresses in `zones/generated/<name>/zone.json`; `zone-up` reads the sequencer key automatically.
> `zone.json` also stores `zoneFactory`, and `just zones::deploy-router` appends `swapAndDepositRouter`.

Once running, generate a user wallet and deposit some tokens:

```bash
# Generate a wallet
cast wallet new
# Save the private key and address
export PRIVATE_KEY="0x<your-wallet-private-key>"
ADDR=$(cast wallet address "$PRIVATE_KEY")

# Fund the wallet on L1 (testnet faucet)
cast rpc tempo_fundAddress "$ADDR" --rpc-url "$L1_RPC_URL"

# Approve the portal and make a deposit to the zone
export L1_PORTAL_ADDRESS=$(jq -r '.portal' zones/generated/my-zone/zone.json)
just zones::max-approve-portal
just zones::send-deposit 1000000

# Check your balance on the zone
just zones::check-balance "$ADDR"
```

See [Interact with the Zone](#6-interact-with-the-zone) for withdrawals and redacted RPC usage.

For a fully local development stack, use Foundry 1.8 or newer, or a nightly
build from July 11, 2026 or later. Run Anvil in Tempo mode and point the dev
command at its WebSocket endpoint:

```bash
# Terminal 1
anvil --network tempo --block-time 1

# Terminal 2
cargo run --release --bin tempo-zone -- dev \
  --l1.rpc-url ws://127.0.0.1:8545
```

This uses the protocol-managed ZoneFactory to create a portal, writes the generated zone files to
`/tmp/tempo-zone-dev`, and serves the zone HTTP RPC at `http://127.0.0.1:9545`.
The configured dev key must own the native ZoneFactory. Stock owner-gated T9 chains require an
ownership transfer before provisioning; separate factory-owner credentials are not yet supported.

Older Anvil builds are rejected because they mine Ethereum header hashes and only
add Tempo fields to the RPC response. Zones require canonical Tempo header hashes
to verify L1 ancestry.

To restart the zone later:

```bash
just zones::zone-up my-zone false release
```

## Step-by-Step Guide

### Prerequisites

- [Rust toolchain](https://rustup.rs/)
- [Foundry](https://book.getfoundry.sh/getting-started/installation) (`cast`, `forge`)
- [`just`](https://github.com/casey/just#packages)
- [`jq`](https://jqlang.github.io/jq/download/)

### 1. Set the L1 RPC URL

All zone commands need an L1 RPC URL.

The zone chain ID is domain-separated by that L1's chain ID. For parent chain ID
`4217` (Tempo mainnet), it is `421700000 + zone_id`; for `42431` (Moderato), it is
`1424310000 + zone_id`. Zone IDs outside each reserved production range are rejected
rather than wrapped. For any other parent in `1..=1048574`, the chain ID is
`(parent_chain_id << 32) | zone_id`. These generic IDs are intentionally high, cannot
collide with the production ranges, and remain safe for JavaScript tooling and legacy
EIP-155 `v` values. Every devnet must use a unique parent chain ID to prevent transaction
replay between it and other devnets.

**Moderato testnet:**
```bash
export L1_RPC_URL="wss://rpc.moderato.tempo.xyz"
```

**Devnet:**
```bash
export L1_RPC_URL="wss://rpc.devnet.tempoxyz.dev"
```

### 2. Generate Admin and Sequencer Keys

The admin controls portal governance such as token enablement, per-token deposit pause/resume, and capability abdication. The sequencer is the operator that builds zone blocks, processes deposits, submits batch proofs back to L1, and may pause the portal. The same key may be used for both authorities, but load it into both `ADMIN_KEY` and `SEQUENCER_KEY` when that is intentional.

```bash
cast wallet new
cast wallet new
```

Save both **addresses** and **private keys**.

```bash
export ADMIN_KEY="0x<admin-private-key>"
export SEQUENCER_KEY="0x<your-private-key>"
ADMIN_ADDR=$(cast wallet address "$ADMIN_KEY")
SEQUENCER_ADDR=$(cast wallet address "$SEQUENCER_KEY")
```

### 3. Fund the Admin and Sequencer on L1

The sequencer needs pathUSD on L1 to pay for the `createZone` transaction and deposit fees. The admin needs funds for later governance calls.

```bash
cast rpc tempo_fundAddress "$ADMIN_ADDR" --rpc-url "$L1_RPC_URL"
cast rpc tempo_fundAddress "$SEQUENCER_ADDR" --rpc-url "$L1_RPC_URL"
```

Verify the balance:

```bash
cast call 0x20C0000000000000000000000000000000000000 \
  "balanceOf(address)(uint256)" "$SEQUENCER_ADDR" \
  --rpc-url "$L1_RPC_URL"
```

View on explorer: `https://explore.moderato.tempo.xyz/address/<SEQUENCER_ADDR>`

### 4. Create the Zone on L1

This creates a ZonePortal through the protocol-managed factory, wired to the shared ZoneMessenger, and generates the zone's genesis file:

```bash
export PRIVATE_KEY="$SEQUENCER_KEY"
just zones::create-zone my-zone
```

The default is open account access and open callback targeting. No account or gateway
addresses are required, and the admin and sequencer are not added implicitly.

The two controls are independent and remain mutable after creation:

| Control | Open (default) | Restricted mode |
|---------|----------------|-----------------|
| Account access | Does not enforce account membership | `closed` requires the `Account` role for deposits, refunds, and plain withdrawals; no assigned accounts denies all accounts |
| Callback targets | Does not enforce callback roles | `enforced` requires callback targets to have the `CallbackGateway` role |

Changing a mode does not clear the stored roles. To create and start a closed zone
with enforced callback targets in one command:

```bash
export ZONE_ALLOWED_ACCOUNTS="0x<account>,0x<account>"
export ZONE_GATEWAYS="0x<gateway>"
just zones::deploy-zone restricted-zone pathusd closed enforced
```

To choose the initial TIP-20 enabled on the portal, pass it as the second positional argument:

```bash
just zones::create-zone my-zone alphausd
```

This creates `zones/generated/my-zone/` containing:
- **`genesis.json`** — Zone L2 genesis state (system contracts, fee token, chain ID, etc.)
- **`zone.json`** — Deployment metadata (portal address, zone ID, anchor block, `zoneFactory`, public `admin` / `sequencer` addresses, and optional saved keys/router metadata)

This initial token controls the first L1 TIP-20 the portal accepts and mirrors onto the zone. The zone's fee token in genesis remains `pathUSD`.

You can also run the xtask directly for more control. Set `ZONE_FACTORY_OWNER_KEY` for that
invocation instead of passing a key argument:

```bash
ZONE_FACTORY_OWNER_KEY="$SEQUENCER_KEY" cargo xtask zones create-zone \
  --output zones/generated/my-zone \
  --initial-token 0x20c0000000000000000000000000000000000001 \
  --admin "$ADMIN_ADDR" \
  --sequencer "$SEQUENCER_ADDR"
```

`create-zone` requires the admin address explicitly. Keep the matching `ADMIN_KEY`
available for admin-only portal calls such as changing either mode or account roles,
enabling tokens, and pausing or resuming deposits.

#### Safe-owned ZoneFactory

When the ZoneFactory owner is a Safe (as on mainnet), creation takes two runs of the same
command. First, replace `ZONE_FACTORY_OWNER_KEY` with `--safe-address` and `--safe-output`:

```bash
unset ZONE_FACTORY_OWNER_KEY
cargo xtask zones create-zone \
  --output zones/generated/my-zone \
  --l1-rpc-url https://rpc.tempo.xyz \
  --zone-factory 0x5aF2000000000000000000000000000000000000 \
  --initial-token 0x20c0000000000000000000000000000000000000 \
  --admin "$ADMIN_ADDR" \
  --threshold 2 \
  --sequencer "$SEQUENCER_1" --sequencer "$SEQUENCER_2" --sequencer "$SEQUENCER_3" \
  --safe-address 0x<factory-owner-safe> \
  --safe-output create-zone.json
```

This run never signs or broadcasts. It requires the Safe to be the current ZoneFactory owner
and to report a nonzero `getThreshold()`, simulates `createZone` from the Safe, and writes an
unsigned Transaction Builder file. It refuses to overwrite an existing output file. The initial
token must already have a TIP-403 transfer policy binding; `migrateTransferPolicyIds` is
permissionless, so any funded account can migrate a legacy token first.

Import the file in Safe's Transaction Builder, check the calldata printed by the command
against what signers see, collect approvals, and execute. `genesis.json` and `zone.json` are
not written yet, because the zone ID, portal, and genesis anchor block only exist once the
transaction executes. After execution, rerun the same command with the execution transaction
hash in place of the Safe options (the first run prints this command):

```bash
cargo xtask zones create-zone \
  --output zones/generated/my-zone \
  ...same zone arguments... \
  --creation-tx 0x<execution-tx-hash>
```

`--creation-tx` works for any already-mined `createZone` transaction, including a direct-key
run that was interrupted before genesis was written. It requires exactly one `ZoneCreated`
event from `--zone-factory` and fails unless its initial token, modes, admin, sequencers, and
threshold match the arguments. Allowed accounts, gateways, and the RPC URL are not in that
event, so pass the same values as the proposal for an accurate `zone.json`.

### Updating closed-loop access

Configure memberships before enabling their corresponding enforcement mode so existing
traffic is not denied during the transition:

```bash
export L1_RPC_URL=https://...
export L1_PORTAL_ADDRESS=0x<portal>
export ADMIN_KEY=0x<portal-admin-private-key>

just zones::set-allowed-account 0x<account> true
just zones::set-gateway 0x<gateway> true
just zones::set-access-mode true
just zones::set-gateway-mode true
```

If the portal admin is a Safe, have `tempo-xtask` simulate each call from the Safe and
create an unsigned Safe Transaction Builder file instead of setting `ADMIN_KEY`:

```bash
export L1_RPC_URL=https://...
export L1_PORTAL_ADDRESS=0x<portal>
export SAFE_ADDRESS=0x<safe>
unset ADMIN_KEY

cargo xtask zones set-allowed-account 0x<account> --allowed \
  --safe-address "$SAFE_ADDRESS" \
  --safe-output allow-account.json

cargo xtask zones set-gateway 0x<gateway> --allowed \
  --safe-address "$SAFE_ADDRESS" \
  --safe-output allow-gateway.json
```

Import each JSON file in Safe's Transaction Builder, collect the configured approvals,
and execute it. Safe proposal mode requires the supplied Safe to equal the current portal
admin, requires deployed bytecode at that address, and simulates the portal call before
creating the file. The admin contract must also expose Safe's `getThreshold()` view and
report a nonzero threshold. Proposal mode never signs or broadcasts a transaction, and it
refuses to overwrite an existing output file. Omit `--allowed` to create a role-revocation
proposal. The same `--safe-address` and `--safe-output` options work with
`set-access-mode` and `set-gateway-mode`; omit `--enforced` to disable the corresponding
mode.

Account and gateway roles are mutually exclusive. To move an address between roles,
remove its current role before adding the new one. Disabling enforcement leaves stored
roles intact, so they take effect again if the mode is re-enabled.

To remove access, revoke the role directly:

```bash
just zones::set-allowed-account 0x<account> false
just zones::set-gateway 0x<gateway> false
```

Revocations apply when each portal or zone-side action executes. In-flight destinations
and gateways that have been revoked bounce back; revoked refund recipients cannot claim
parked refunds until their account role is restored. Before closing access or removing a
role, confirm that affected deposits, withdrawals, callbacks, and refunds have completed.

Direct-key mode verifies the signer is the current portal admin, waits for the transaction,
and reads the resulting mode or role back from the portal. Safe proposal mode stops after
simulation and file creation, so verify the resulting role or mode after the Safe executes
the imported transaction.

### 5. Start the Zone Node

```bash
just zones::zone-up my-zone false release
```

Use `release` profile for production (recommended). Omit it for debug builds during development.

The zone node will:
- Listen on `http://localhost:8546` for JSON-RPC
- Subscribe to L1 for deposit events and backfill from the genesis anchor block
- Build one zone block per L1 block (catches up at full speed during sync)
- Submit batch proofs to L1 every 60s (or immediately when withdrawals are pending)
- Process withdrawals from the zone back to L1

To reset the zone's datadir and start fresh:

```bash
just zones::zone-up my-zone true release
```

The zone node stores data in `/tmp/tempo-zone-<name>/`.

### 6. Interact with the Zone

#### Create and fund a user wallet

The `just` commands below sign transactions with `PRIVATE_KEY`. Generate a wallet and fund it on L1 via the testnet faucet:

```bash
cast wallet new
export PRIVATE_KEY="0x<your-wallet-private-key>"
ADDR=$(cast wallet address "$PRIVATE_KEY")
cast rpc tempo_fundAddress "$ADDR" --rpc-url "$L1_RPC_URL"
```

#### Deposit from L1 to Zone

All user deposits are encrypted. Approve the portal to spend your tokens, then deposit:

The portal's `deposit(...)` entrypoint accepts encrypted arguments and forwards to the same
implementation as `depositEncrypted(...)`; first-party tooling uses `deposit`.

> This deposit ABI is not compatible with earlier plaintext-deposit zones. Recreate an existing development zone after upgrading.

```bash
export L1_PORTAL_ADDRESS=$(jq -r '.portal' zones/generated/my-zone/zone.json)
just zones::max-approve-portal
just zones::send-deposit 1000000                       # deposit to your own address
just zones::send-deposit 1000000 <recipient-address>   # deposit to a specific address
```

#### Encryption Key Setup

Encrypted deposits hide the recipient address and memo on-chain using ECIES encryption to the sequencer's public key. Only the sequencer can decrypt them during block building.

```bash
# The sequencer must first register their encryption key (done automatically by deploy-zone)
# For manual setup:
PRIVATE_KEY="$SEQUENCER_KEY" cargo xtask zones set-encryption-key \
  --portal "$L1_PORTAL_ADDRESS" \
  --l1-rpc-url "$L1_RPC_URL"

# Send a deposit
just zones::send-deposit 1000000                       # to your own address
just zones::send-deposit 1000000 <recipient-address>   # to a specific address
```

For shared-key rotations, pass the currently deployed
`--deposit-decryption-keys-file` to `tempo-xtask zones admin encryption-key prepare`
with `--existing-decryption-keys-file`. Deploy its merged output before
registering the replacement encryption key, restart every node that may
sequence, and confirm the nodes are healthy. Keep every previous key in the
file while it remains Portal grace-valid or has queued deposits. Retire a
specific old key only after Portal expiry and deposit-queue drainage. File order
does not matter: finalized Portal registrations bind each configured key to its
on-chain index. The active sequencer key is included automatically.

Set `ZONE_RPC_URL` to poll the zone for processing confirmation:

```bash
export ZONE_RPC_URL="http://localhost:8546"
just zones::send-deposit 1000000
```

#### Check balance on the zone

```bash
just zones::check-balance "$ADDR"
```

#### Withdraw from Zone to L1

Approve the outbox, then request a withdrawal:

```bash
just zones::max-approve-outbox
just zones::send-withdrawal 1000000                       # withdraw to your own address
just zones::send-withdrawal 1000000 <recipient-address>   # withdraw to a specific address
```

The sequencer includes the withdrawal in the next batch submission to L1 and processes it automatically.

#### Router Swap + Deposit Demo (Same Zone)

This demo exercises the `SwapAndDepositRouter` flow against a running zone. It creates temporary `AlphaUSD` and `BetaUSD` tokens on L1, seeds matching StablecoinDEX liquidity, withdraws `AlphaUSD` from the zone to the router, swaps on L1, and deposits `BetaUSD` back into the same zone. The routed callback payload includes a public `tempoRefundRecipient` for the downstream portal deposit; set `ROUTER_BOUNCEBACK_RECIPIENT` to a refund-specific burner or stealth address you control if you do not want a later refund to point at the encrypted zone recipient. If the portal does not already have the current sequencer encryption key registered, the demo registers it automatically before building the routed callback payload.

Prerequisites:
- A running zone with an active sequencer
- `L1_RPC_URL` and `PRIVATE_KEY` set
- `zones/generated/<name>/zone.json` present
- `SEQUENCER_KEY` set if `zone.json` does not already contain `sequencerKey`
- `ADMIN_KEY` set if `zone.json` does not already contain `adminKey` and the portal admin differs from the sequencer

Deploy the router once for the zone:

```bash
just zones::deploy-router my-zone
```

That command saves the router address to `zones/generated/my-zone/zone.json` as `swapAndDepositRouter`.

Run the demo:

```bash
just zones::demo-swap-and-deposit my-zone
```

Run with a dedicated routed-deposit refund address:

```bash
ROUTER_BOUNCEBACK_RECIPIENT=0xYourControlledBurnerAddress just zones::demo-swap-and-deposit my-zone
```

Optional parameters:

```bash
just zones::demo-swap-and-deposit my-zone 100000000 0
```

This is a same-zone demo only. The command creates its own temporary tokens and DEX liquidity automatically, so you do not need to pre-create assets or seed the order book yourself.

#### Query the Redacted RPC

The redacted RPC (port 8544) requires a signed auth token derived from your private key. This ensures only the account owner can query their own scoped state. The operator RPC (port 8545) is restricted to the zone operator and exposes full state plus administrative methods.

Use the built-in helper if you only want a quick balance check:

```bash
just zones::check-balance-redacted my-zone
```

For direct RPC calls, `just zones::zone-auth-token` generates a 10-minute token from `zones/generated/<name>/zone.json`, and `cast rpc` forwards it with `X-Authorization-Token`.
HTTP header names are case-insensitive, so `x-authorization-token` works too, but the examples here use the canonical casing from the spec.

One-liner to verify the redacted endpoint and inspect the authenticated account:

```bash
cast rpc zone_getAuthorizationTokenInfo \
  --rpc-url http://localhost:8544 \
  --rpc-headers "X-Authorization-Token: $(just zones::zone-auth-token my-zone)"
```

If you want to make multiple requests, generate the token once and reuse it:

```bash
TOKEN=$(just zones::zone-auth-token my-zone)

cast rpc zone_getAuthorizationTokenInfo \
  --rpc-url http://localhost:8544 \
  --rpc-headers "X-Authorization-Token: $TOKEN"

cast rpc zone_getEncryptionKey \
  --rpc-url http://localhost:8544 \
  --rpc-headers "X-Authorization-Token: $TOKEN"

cast rpc eth_blockNumber \
  --rpc-url http://localhost:8544 \
  --rpc-headers "X-Authorization-Token: $TOKEN"
```

To query your own TIP-20 balance directly with `eth_call`, derive the authenticated account from `PRIVATE_KEY`, encode `balanceOf(address)`, and send the call through the private endpoint:

```bash
ADDR=$(cast wallet address "$PRIVATE_KEY")
DATA=$(cast calldata "balanceOf(address)" "$ADDR")

cast rpc eth_call \
  "{\"from\":\"$ADDR\",\"to\":\"0x20C0000000000000000000000000000000000000\",\"data\":\"$DATA\"}" \
  latest \
  --rpc-url http://localhost:8544 \
  --rpc-headers "X-Authorization-Token: $TOKEN"
```

Swap the `to` address above if you want to query a different zone TIP-20.

#### Check portal status on L1

```bash
PORTAL=$(jq -r '.portal' zones/generated/my-zone/zone.json)
HTTP_RPC=$(echo "$L1_RPC_URL" | sed 's|^wss://|https://|' | sed 's|^ws://|http://|')

# Last L1 block synced by the zone
cast call "$PORTAL" "lastSyncedTempoBlockNumber()(uint64)" --rpc-url "$HTTP_RPC"

# Withdrawal queue status (head == tail means empty)
cast call "$PORTAL" "withdrawalQueueHead()(uint256)" --rpc-url "$HTTP_RPC"
cast call "$PORTAL" "withdrawalQueueTail()(uint256)" --rpc-url "$HTTP_RPC"
```

## Token & Policy Management (TIP-403)

Tempo L1 supports transfer policies via the TIP-403 registry. You can create new TIP-20 tokens, assign transfer policies (whitelist, blacklist, or compound), and manage membership — all from L1. The zone picks up policy changes automatically via the L1 subscriber.

### Create a New Token

```bash
# Create a TIP-20 token named "MyUSD" with symbol "MUSD"
# The address is derived from your wallet + salt (not the name/symbol).
# Use a different salt to create multiple tokens from the same wallet.
just zones::create-token MyUSD MUSD
just zones::create-token AnotherUSD AUSD 0x0000000000000000000000000000000000000000000000000000000000000001
# → Token created! Address: 0x20C0...

# Grant yourself ISSUER_ROLE and mint tokens
just zones::grant-issuer-role <token-address>
just zones::mint-tokens <token-address>               # 1B tokens to yourself
just zones::mint-tokens <token-address> <to> 5000000  # 5 tokens to someone else

# Set a supply cap (optional)
just zones::set-supply-cap <token-address> 1000000000000
```

### Enable a Token on the Zone

To deposit a custom token into the zone, it must be enabled on the ZonePortal. By default the portal starts with `pathUSD`, or whichever TIP-20 you selected with `just zones::create-zone <name> <token>` or `just zones::deploy-zone <name> <token>`. Additional tokens must exist on L1 and be enabled by the portal admin.

```bash
# Enable a token by address (requires ADMIN_KEY, L1_RPC_URL, L1_PORTAL_ADDRESS)
export ADMIN_KEY="0x<your-admin-key>"
export L1_PORTAL_ADDRESS=$(jq -r '.portal' zones/generated/my-zone/zone.json)
just zones::enable-token <token-address>

# Well-known aliases also work
just zones::enable-token pathusd
just zones::enable-token alphausd
```

If `ZONE_RPC_URL` is set (defaults to `http://localhost:8546`), the command waits for the zone to process the L1 block and confirms the token is available on L2.

To perform only the L1 portal update through `tempo-xtask`, use the same address or alias:

```bash
cargo xtask zones enable-token <token-address>
cargo xtask zones enable-token alphausd
```

The xtask waits for the L1 receipt and verifies `ZonePortal.isTokenEnabled`, but unlike the
Justfile recipe it does not wait for a running zone node to ingest the enablement. If the
portal admin is a Safe, create an unsigned Transaction Builder proposal instead:

```bash
unset ADMIN_KEY
cargo xtask zones enable-token <token-address> \
  --safe-address 0x<safe> \
  --safe-output enable-token.json
```

The portal admin can also pause and resume deposits for an enabled token (withdrawals are unaffected). These calls are `onlyAdmin`, so they use the same `ADMIN_KEY` as `enable-token`:

```bash
just zones::pause-deposits <token-address>
just zones::resume-deposits <token-address>
```

Once the token is enabled, approve the portal and deposit as usual — just pass the token address:

```bash
# Approve the portal to spend the custom token
just zones::max-approve-portal <token-address>

# Deposit the custom token into the zone
just zones::send-deposit 1000000 "" 0x0000000000000000000000000000000000000000000000000000000000000000 <token-address>

# Check balance on the zone (pass the token address)
just zones::check-balance "$ADDR" <token-address>
```

### Verify Closed-Loop Configuration

After deploying the Earn stack and configuring its ZonePortal, run the read-only automated checks
and print the current account allowlist for manual confirmation using the Earn router:

```bash
L1_RPC_URL=https://... just zones::verify-closed-loop \
  0x<earn-router>
```

The verifier derives the Zone and Portal from the router, finds the Zone's deployment event, and
reconstructs the current role and enabled-token sets from Portal events through one pinned L1 block.
It requires the Earn router to be the only `CallbackGateway` and the boundary-crossing tokens
(`privateAsset` and `earnShare`) to be the exact enabled-token set with active deposits. The vault
asset remains on L1 and is not Portal-enabled unless it is also the private asset. The current
`Account` role set is printed in sorted order and must be compared manually with the approved
deployment record; account membership is not part of the automated pass/fail result. Verification
performs no transactions and requires no private key.

### Blacklist a Sender

This example creates a blacklist policy that prevents a specific address from sending transfers, while still allowing them to receive deposits.

```bash
# 1. Create a blacklist policy (type=1)
just zones::create-policy 1
# → Policy ID: 2

# 2. Add the address to the blacklist
just zones::modify-blacklist 2 0x<address-to-block>

# 3. Wrap in a compound policy so only the SENDER role is restricted
#    (recipient and mint-recipient use policy 1 = allow-all)
just zones::create-compound-policy 2 1 1
# → Policy ID: 3

# 4. Assign the compound policy to the token
just zones::set-transfer-policy 0x20C0000000000000000000000000000000000000 3

# 5. Verify
just zones::check-authorized 2 0x<address-to-block>
# → authorized=false
```

> **Why compound?** A simple blacklist blocks an address as both sender and recipient. A compound policy lets you blacklist only the sender role while keeping deposits (mint-recipient) and incoming transfers (recipient) open.

### Other Policy Commands

| Command | Description |
|---------|-------------|
| `just zones::create-policy [type]` | Create a policy (`0`=whitelist, `1`=blacklist) |
| `just zones::create-compound-policy <sender> <recipient> [mint]` | Create a compound policy from sub-policies |
| `just zones::modify-whitelist <policy-id> <account> [allowed]` | Add/remove from a whitelist |
| `just zones::modify-blacklist <policy-id> <account> [restricted]` | Add/remove from a blacklist |
| `just zones::set-transfer-policy <token> <policy-id>` | Assign a transfer policy to a token |
| `just zones::check-authorized <policy-id> <account>` | Check if an address is authorized |
| `just zones::token-policy <token>` | Read a token's current transfer policy ID |
| `just zones::create-token <name> <symbol> [salt]` | Create a new TIP-20 token on L1 |
| `just zones::mint-tokens <token> [to] [amount]` | Mint tokens (requires ISSUER_ROLE) |
| `just zones::grant-issuer-role <token> [to]` | Grant ISSUER_ROLE on a token |
| `just zones::set-supply-cap <token> [cap]` | Set a token's supply cap |

### Blacklist Demo (End-to-End)

`just zones::demo-blacklist` runs a self-contained scenario that exercises the full TIP-20 + TIP-403 lifecycle in a single command. It creates a fresh token, deposits into the zone, blacklists an address, proves that encrypted deposits to that address bounce, unblacklists the address, proves deposits now succeed, and withdraws back to L1.

This is useful for verifying that transfer-policy enforcement works end-to-end across L1 and L2, or for demoing the blacklist feature to others.

```bash
export PRIVATE_KEY="0x<token-admin-and-depositor-private-key>"
export L1_PORTAL_ADDRESS=$(jq -r '.portal' zones/generated/my-zone/zone.json)
# If zones/generated/*/zone.json does not contain the matching adminKey, set ADMIN_KEY
# to the private key for the portal's on-chain admin.

just zones::demo-blacklist              # default deposit amount = 500,000
just zones::demo-blacklist 1000000      # custom deposit amount
just zones::demo-blacklist 500000 http://localhost:8546 zones/generated/my-zone  # explicit metadata directory
```

The demo walks through 9 steps, printing every transaction with an explorer link:

1. **Create token** — deploys a fresh TIP-20 "DemoUSD" via `TIP20Factory` (random salt each run)
2. **Configure token** — sets supply cap, grants `ISSUER_ROLE`, mints tokens, approves portal
3. **Enable on zone** — portal admin calls `enableToken` on the portal (uses `ADMIN_KEY`, or auto-discovers the matching `zones/generated/<name>/zone.json` and reads `adminKey` with `sequencerKey` as a legacy fallback)
4. **Deposit** — plain deposit so the `PRIVATE_KEY` wallet has L2 funds
5. **Blacklist** — creates a TIP-403 blacklist policy, adds a fresh target wallet, assigns the policy to the token
6. **Deposit → bounce** — sends a deposit to the blacklisted target; zone rejects it and returns funds to sender
7. **Unblacklist** — removes the target from the blacklist on L1
8. **Deposit → success** — the same deposit now goes through
9. **Withdraw** — target withdraws tokens from zone back to L1

Prerequisites: a running zone with the sequencer producing blocks, the `PRIVATE_KEY` wallet funded with pathUSD on L1, and portal admin authority available via `ADMIN_KEY` or a saved `adminKey` in the matching `zones/generated/<name>/zone.json` (the demo deposits a small amount to the target for L2 gas fees).

## Architecture

```mermaid
graph TB
    subgraph L1["Tempo L1 (Moderato)"]
        Factory["ZoneFactory (shared)"]
        Portal["ZonePortal (per-zone)<br/>deposits · batch proofs · withdrawals"]
        Factory -->|createZone| Portal
    end

    subgraph L2["Zone L2 Node"]
        direction TB
        Tasks["Sequencer Tasks<br/>• L1 subscriber (deposit backfill + live)<br/>• Zone engine (L1-driven block building)<br/>• Zone monitor (batch submission to L1)<br/>• Withdrawal processor (L1 queue drain)"]
    end

    Portal -- "WSS subscription<br/>(deposits, headers)" --> Tasks
    Tasks -- "submitBatch / processWithdrawals" --> Portal
```

### Precompiles

Zones inherit the Tempo L1 EVM but replace, disable, or pass through each precompile depending on whether it is relevant in the zone context. The zone also adds new precompiles for L1 state access, privacy, and zone-specific transaction context.

#### Tempo L1 Precompiles on Zones

| Precompile | Address | Zone Behavior |
|------------|---------|---------------|
| Standard EVM (ecrecover, SHA-256, etc.) | `0x01`–`0x0a`, `0x0100` on T1C+ | **Unchanged** — standard Ethereum precompiles inherited from Tempo's active hardfork (Prague pre-T1C, Osaka at T1C+) are available as-is. |
| TIP-20 tokens | `0x20C0…` prefix | **Adapted** — upstream Tempo TIP-20 business logic runs over zone-local token state and exact-block L1 policy state, with zone privacy (caller-scoped reads), fixed gas for transfers, and bridge authorization for mint/burn. |
| TIP20Factory | `0x20FC…0000` | **Disabled** — token creation is L1-owned; `ZoneInbox` directly activates bridged TIP-20 tokens during `advanceTempo`. |
| TIP403Registry | `0x403C…0000` | **Adapted** — the upstream Tempo registry executes read-only against raw L1 storage at the exact finalized block recorded in `TempoState`. Mutating calls (`createPolicy`, `modifyPolicyWhitelist`, etc.) revert because policy state is managed on L1. |
| ZoneFeeManager | `0xfeec…0001` | **Replaced** — no user/validator preferences or FeeAMM routing. The explicit transaction token (or portal creation-time default) is escrowed directly, accrued by beneficiary/token, and readable or claimable only by that beneficiary. |
| StablecoinDEX | `0xdec0…0000` | **Disabled** — not registered on zones, so the address behaves like an empty account. Users on zones can trade on the StablecoinDEX on Tempo via the bridge. |
| NonceManager | `0x4E4F…0000` | **Unchanged** — same implementation as L1, runs locally on zone state. |
| ValidatorConfig (legacy) | `0xCCCC…0000` | **Not registered** — zones do not run validators, so the precompile is not loaded. |
| ValidatorConfigV2 | `0xCCCC…0001` | **Not registered** — zones do not run validators, so the precompile is not loaded. |
| AccountKeychain | `0xAAAA…0000` | **Unchanged** — same implementation as L1, runs locally on zone state. |
| AddressRegistry | `0xFDC0…0000` | **Not registered** — the address has no zone precompile implementation. |
| SignatureVerifier | `0x5165…0000` | **Not registered** — the address has no zone precompile implementation. |

#### Zone-Only Precompiles

| Precompile | Address | Description |
|------------|---------|-------------|
| TempoStateReader | `0x1c00…0004` | Reads L1 contract storage from zone contracts via the L1 state cache. |

## Configuration

### Key Addresses

| Contract | Address |
|----------|---------|
| pathUSD (TIP-20) | `0x20C0000000000000000000000000000000000000` |
| ZoneFactory | `0x5aF2000000000000000000000000000000000000` |
| ZonePortal implementation | `0x5AD1000000000000000000000000000000000000` |
| Zone verifier | `0x5a56000000000000000000000000000000000000` |
| ZoneMessenger | `0x5A4d000000000000000000000000000000000000` |

The xtasks use this Moderato `ZoneFactory` as their built-in default: `create-zone` and `zone-info` point at it automatically, and `deploy-router` uses `zoneFactory` from `zone.json` before falling back to this address. Pass `--zone-factory` or set `ZONE_FACTORY` to override it.

### Verifying the ZoneFactory

TIP-1091 makes the factory and its shared dependencies protocol-managed accounts. Verify them at their fixed addresses:

```bash
export ZONE_FACTORY=0x5aF2000000000000000000000000000000000000

cast code "$ZONE_FACTORY" --rpc-url "$ETH_RPC_URL"
cast call "$ZONE_FACTORY" "nextZoneId()(uint32)" --rpc-url "$ETH_RPC_URL"
cast code 0x5AD1000000000000000000000000000000000000 --rpc-url "$ETH_RPC_URL"
cast code 0x5a56000000000000000000000000000000000000 --rpc-url "$ETH_RPC_URL"
cast code 0x5A4d000000000000000000000000000000000000 --rpc-url "$ETH_RPC_URL"
```

### Zone Node CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--l1.rpc-url` | (required) | Certified Tempo follower WebSocket RPC URL |
| `--l1.portal-address` | (from zone.json) | ZonePortal contract on L1 |
| `--zone.id` | (deprecated) | Optional compatibility check against the zone ID encoded in the genesis chain ID. |
| `--sequencer` | false | Enable sequencer mode for block production and withdrawal batch submission |
| `--sequencer-key-file` | (required for sequencing) | Owner-readable file or FIFO containing the sequencer private key |
| `--sequencer.enable-prover` | false | Run detached SPF validation; supported by sequencers and `rpc_only` P2P followers |
| `--sequencer.prover-address` | (optional) | Repeatable `HARDFORK=HOST:PORT` assignment selected by the live L1 fork; missing forks stop proving and the readiness gauge flags current/next-72-hour gaps |
| `--sequencer.prover-attestation-policy` | (required for remote proving) | JSON PCR0–2 allowlist shared by all endpoints; authenticates the transport and controls evidence freshness without changing L1 verifier policy |
| `--shadow-prover.pcrs` | (optional) | Pin PCR0,PCR1,PCR2 (three comma-separated, nonzero 48-byte hex measurements) to authenticate remote Nitro proofs on an RPC follower |
| `--deposit-decryption-keys-file` | (optional) | File containing additional historical or pre-provisioned deposit decryption keys, one hex key per line |
| `--zone.batch-interval-blocks` | 120 | Zone blocks between empty withdrawal batch boundaries / L1 submissions (~1 minute at Tempo's 500 ms block time) |
| `--zone.poll-interval-secs` | 1 | Fallback interval for reconciling the canonical Zone head when no native notification arrives |
| `--withdrawal-poll-interval-secs` | 5 | How often (seconds) the withdrawal processor polls the L1 queue |
| `--withdrawal-max-batch-gas` | 10000000 | Maximum planned gas for one `processWithdrawals` transaction (up to 20000000); an oversized FIFO head is still sent alone |
| `--withdrawal-max-in-flight-batches` | 8 | Maximum ordered withdrawal transactions kept concurrently in flight |
| `--http.port` | 8546 | HTTP JSON-RPC port |
| `--redacted-rpc.port` | 8544 | Redacted RPC server port |
| `--redacted-rpc.max-auth-token-validity-secs` | 2592000 | Maximum auth token validity the redacted RPC accepts, in seconds. The effective limit is capped at 30 days. |

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `L1_RPC_URL` | Yes | Certified Tempo follower WebSocket RPC URL (`wss://...`) |
| `SEQUENCER_KEY` | For short-lived tooling | Sequencer private key for `just zones::create-zone` and xtasks; not accepted by the node |
| `SEQUENCER_KEY_FILE` | For sequencing | Owner-readable file or FIFO containing the sequencer private key |
| `SEQUENCER_ENABLE_PROVER` | No | Enable detached SPF validation, including on an `rpc_only` P2P follower |
| `SEQUENCER_PROVER_ADDRESS` | No | Comma-separated `HARDFORK=HOST:PORT` assignments; see the [prover upgrade runbook](../../bin/prover/enclave/README.md#upgrading-across-an-l1-hardfork) |
| `SEQUENCER_PROVER_ATTESTATION_POLICY` | For remote proving | JSON PCR0–2 allowlist and evidence-freshness policy path shared by the configured endpoints |
| `SHADOW_PROVER_PCRS` | No | Three comma-separated 48-byte enclave measurements for local shadow verification |
| `DEPOSIT_DECRYPTION_KEYS_FILE` | During encryption-key rotation | Additional historical or pre-provisioned deposit decryption keys, one hex key per line |
| `ADMIN_KEY` | For portal governance | Portal admin private key for `enableToken` / deposit pause controls. `SEQUENCER_KEY` only works for legacy zones where admin == sequencer. |
| `PRIVATE_KEY` | For transactions | Key for L1 transactions (deposits, approvals) |
| `L1_PORTAL_ADDRESS` | For deposits | ZonePortal address (from `zone.json`) |
| `ROUTER_BOUNCEBACK_RECIPIENT` | No | Optional controlled burner/stealth address for `demo-swap-and-deposit` routed deposit refunds |
| `REDACTED_RPC_MAX_AUTH_TOKEN_VALIDITY_SECS` | No | Maximum auth token validity the redacted RPC accepts, in seconds. The effective limit is capped at 30 days. |
| `WITHDRAWAL_MAX_BATCH_GAS` | No | Override the per-transaction withdrawal gas budget (maximum 20000000) |
| `WITHDRAWAL_MAX_IN_FLIGHT_BATCHES` | No | Override the maximum number of ordered withdrawal transactions in flight |
| `ZONE_TOKEN` | No | Default initial TIP-20 for `just zones::create-zone` / `just zones::deploy-zone`; defaults to `pathUSD` |
| `ZONE_ALLOWED_ACCOUNTS` | No | Comma-separated initial account membership |
| `ZONE_GATEWAYS` | No | Comma-separated initial callback-target registrations |
| `ZONE_FACTORY` | No | Optional ZoneFactory override; xtasks default to the current Moderato shared deployment |

## Justfile Commands Reference

| Command | Description |
|---------|-------------|
| `just zones::deploy-zone <name> [<tip20>] [open\|closed] [enforced\|open]` | One-shot: keygen → fund → create → genesis → start node |
| `just zones::create-zone <name> [<tip20>] [open\|closed] [enforced\|open]` | Create zone on L1 + generate genesis (requires `PRIVATE_KEY`, `SEQUENCER_KEY`, and `ADMIN_KEY` or `ADMIN_ADDR`) |
| `just zones::deploy-router <name> [dex]` | Deploy `SwapAndDepositRouter` on L1 for the zone and save it to `zone.json` |
| `just zones::verify-closed-loop <earn-router>` | Verify an existing Earn deployment's closed-loop Portal configuration (read-only) |
| `just zones::zone-up <name> [reset] [profile]` | Start the zone node. `reset=true` wipes datadir. `profile=release` for production. |
| `just zones::max-approve-portal [token]` | Approve portal to spend tokens on L1 |
| `just zones::send-deposit [amount] [to] [memo] [token] [rpc]` | Deposit tokens from L1 to the zone with an encrypted recipient and memo |
| `just zones::enable-token <token>` | Enable a TIP-20 token on the portal for bridging (admin only) |
| `just zones::pause-deposits <token>` | Pause deposits for an enabled token on the portal (admin only) |
| `just zones::resume-deposits <token>` | Resume deposits for a paused token on the portal (admin only) |
| `just zones::set-access-mode <true\|false>` | Enable or disable closed-loop account enforcement (admin only) |
| `just zones::set-gateway-mode <true\|false>` | Enable or disable callback gateway enforcement (admin only) |
| `just zones::set-allowed-account <account> <true\|false>` | Add or remove an Account role (admin only) |
| `just zones::set-gateway <account> <true\|false>` | Add or remove a CallbackGateway role (admin only) |
| `just zones::list-enabled-tokens [portal]` | List TIP-20 token addresses enabled on a portal |
| `just zones::max-approve-outbox [token] [rpc]` | Approve outbox to spend tokens on zone |
| `just zones::send-withdrawal [amount] [to] [token] [memo] [gas-limit] [fallback-recipient] [data] [reveal-to] [rpc]` | Withdraw tokens from zone to L1 (defaults to sender) |
| `just zones::demo-swap-and-deposit <name> [amount] [tick] [rpc]` | Self-contained same-zone router demo: create tokens, seed DEX liquidity, swap on L1, deposit output back into the zone; set `ROUTER_BOUNCEBACK_RECIPIENT` for routed deposit refunds |
| `just zones::check-balance <addr> [token] [rpc]` | Check token balance on the zone |
| `just zones::zone-auth-token <name>` | Generate a signed redacted RPC auth token (10 min TTL) |
| `just zones::check-balance-redacted <name> [token] [rpc]` | Check balance via the redacted RPC (auto-generates auth token) |
| `just zones::zone-info <id-or-portal>` | Fetch zone metadata from ZoneFactory |
| `just zones::demo-blacklist [amount] [rpc] [zone-dir]` | End-to-end TIP-20 + TIP-403 blacklist lifecycle demo |
| `just zones::spam-deposits [total] [per-block] [amount] [encrypted] [token] [lead-time]` | Send many deposit transactions to measure portal throughput |
