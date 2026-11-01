# Tempo Zones

**Table of Contents**

- [Abstract](#abstract)
- [Specification](#specification)
  - [Terminology](#terminology)
  - [System Overview](#system-overview)
  - [Access Control](#access-control)
    - [Roles](#roles)
    - [Permission Matrix](#permission-matrix)
  - [Zone Deployment](#zone-deployment)
    - [Chain ID](#chain-id)
    - [Tempo Contracts](#tempo-contracts)
    - [Zone Predeploys](#zone-predeploys)
    - [Zone Token Model](#zone-token-model)
  - [Sequencer Operations](#sequencer-operations)
    - [Multi-Sequencer Topology](#multi-sequencer-topology)
    - [Token Management](#token-management)
    - [Gas Rate Configuration](#gas-rate-configuration)
    - [Encryption Key Management](#encryption-key-management)
    - [Leadership and Sequencer Set Rotation](#leadership-and-sequencer-set-rotation)
    - [Admin Transfer](#admin-transfer)
  - [Deposits](#deposits)
    - [Deposit Fees](#deposit-fees)
    - [Deposit Queue](#deposit-queue)
    - [Deposits](#deposits)
    - [Onchain Decryption Verification](#onchain-decryption-verification)
    - [Deposit Failures and Bounce-Back](#deposit-failures-and-bounce-back)
  - [Withdrawals](#withdrawals)
    - [Withdrawal Request](#withdrawal-request)
    - [Withdrawal Fees](#withdrawal-fees)
    - [Withdrawal Batching](#withdrawal-batching)
    - [Withdrawal Queue](#withdrawal-queue)
    - [Withdrawal Processing](#withdrawal-processing)
    - [Withdrawal Callbacks](#withdrawal-callbacks)
    - [Withdrawal Failures and Bounce-Back](#withdrawal-failures-and-bounce-back)
    - [Authenticated Withdrawals](#authenticated-withdrawals)
    - [Zone-to-Zone Transfers](#zone-to-zone-transfers)
  - [Zone Execution](#zone-execution)
    - [Fee Accounting](#fee-accounting)
    - [Block Structure](#block-structure)
      - [Multi-block Tempo Imports](#multi-block-tempo-imports)
    - [Block Header Format](#block-header-format)
    - [Privacy Modifications](#privacy-modifications)
  - [Tempo State Reads](#tempo-state-reads)
    - [TempoState Predeploy](#tempostate-predeploy)
    - [Tempo Follower Mode](#tempo-follower-mode)
    - [Header Finalization](#header-finalization)
    - [L1 Storage Reads](#l1-storage-reads)
    - [Staleness and Finality](#staleness-and-finality)
  - [TIP-403 Policies](#tip-403-policies)
    - [Policy Enforcement on Zones](#policy-enforcement-on-zones)
    - [Policy Inheritance](#policy-inheritance)
  - [Redacted RPC](#redacted-rpc)
    - [Authorization Tokens](#authorization-tokens)
    - [Signature Types](#signature-types)
    - [Method Access Control](#method-access-control)
    - [Block Responses](#block-responses)
    - [Event Filtering](#event-filtering)
    - [WebSocket Subscriptions](#websocket-subscriptions)
    - [Zone-Specific Methods](#zone-specific-methods)
    - [Error Codes](#error-codes)
  - [Proving System](#proving-system)
    - [State Transition Function](#state-transition-function)
    - [Witness Structure](#witness-structure)
    - [Input Schematic](#input-schematic)
    - [Detailed Input Definitions](#detailed-input-definitions)
    - [Shared Trie Proof Format](#shared-trie-proof-format)
    - [Batch Output](#batch-output)
    - [Block Execution](#block-execution-stateless-prover-execution-function)
    - [Tempo State Witness](#tempo-state-witness)
    - [Nitro Attestation](#nitro-attestation)
    - [Prover Service and Deployment](#prover-service-and-deployment)
  - [Batch Submission](#batch-submission)
    - [submitBatch](#submitbatch)
    - [Verifier Interface](#verifier-interface)
    - [Anchor Block Validation](#anchor-block-validation)
    - [Proof Requirements](#proof-requirements)
  - [Zone Precompiles](#zone-precompiles)
    - [TIP-20 Token Precompile](#tip-20-token-precompile)
  - [Encrypted Deposit Cryptography](#encrypted-deposit-cryptography)
    - [Chaum-Pedersen Verification](#chaum-pedersen-verification)
    - [AES-GCM Decryption](#aes-gcm-decryption)
  - [Contracts and Interfaces](#contracts-and-interfaces)
    - [Common Types](#common-types)
    - [IZoneFactory](#izonefactory)
    - [IZonePortal](#izoneportal)
    - [IZoneMessenger](#izonemessenger)
    - [IWithdrawalReceiver](#iwithdrawalreceiver)
    - [ITempoState](#itempostate)
    - [IZoneInbox](#izoneinbox)
    - [IZoneOutbox](#izoneoutbox)
    - [TIP-403 Registry](#tip-403-registry)
  - [Network Upgrades and Hard Fork Activation](#network-upgrades-and-hard-fork-activation)

---

# Abstract

A Tempo Zone is a private execution environment anchored to Tempo. Inside a zone, balances, transfers, and transaction history are invisible to block explorers, indexers, and other users. Each zone is operated by a sequencer set with one active leader and zero or more followers. The leader is the sole block producer, while followers replicate and validate its blocks and attest to batch-boundary settlement commitments. Threshold-certified batches settle back to Tempo through a proof-agnostic verification system.

Funds enter a zone through deposits on Tempo, where they are locked in the portal. The zone mints equivalent tokens, and users transact privately with balances and transaction history hidden behind authenticated RPC access and execution-level controls. When users withdraw, tokens are burned on the zone and released from the portal on Tempo. Proofs guarantee that the sequencer executed every transaction correctly and cannot forge state transitions. Each portal has two independent, admin-mutable boolean flags: `accessMode` controls account allowlist enforcement for deposits, refunds, and plain withdrawals, while `gatewayMode` controls callback target registration. Disabling either flag disables only its corresponding checks without deleting the stored mapping.

This document specifies the zone protocol: deployment, sequencer operations, deposits, execution, the operator and redacted RPC interfaces, the proving system, batch submission, withdrawals, precompiles, contract interfaces, and the network upgrade process.

# Specification

## Terminology

| Term | Definition |
|------|------------|
| Tempo | The base chain that zones settle to. |
| Zone | A private execution environment anchored to Tempo. |
| Portal | The contract on Tempo that locks deposited tokens and finalizes withdrawals for a zone. |
| Batch | A sequencer-produced commitment covering one or more zone blocks, submitted to Tempo with a proof. |
| Checkpoint-only block | A system-only zone block that authenticates a bounded consecutive Tempo header range without applying portal work. Also called a header-only block in TIP-1096. |
| Admin | The privileged governance role for a zone. Cold/mission-critical key. Controls token enablement. See [Access Control](#access-control). |
| Sequencer | A member of the zone's privileged operational set. The active leader produces blocks and submits batches; followers replicate and validate blocks and attest to settlement commitments. See [Access Control](#access-control). |
| Settlement quorum | The configured threshold of distinct active-sequencer signatures required for `ZonePortal.submitBatch`. |
| Enabled token | A TIP-20 token that the admin has activated for deposits and withdrawals on a zone. Enablement is permanent. |
| TIP-20 | Tempo's fungible token standard. |
| TIP-403 | Tempo's compliance registry. Issuers attach transfer policies (whitelists, blacklists) to TIP-20 tokens. |
| Predeploy | A system contract deployed at a fixed address on the zone at genesis. |
| Allowed account | An address assigned the portal's `Account` role. The role is enforced while `accessMode` is `true` and retained but inactive while it is `false`. |
| ZoneGateway | A Tempo callback contract assigned the portal's `CallbackGateway` role. The role is enforced while `gatewayMode` is `true` and retained but inactive while it is `false`. |

<br>

## System Overview

Each zone is operated by a **sequencer set**. Exactly one active sequencer is the leader for a given Tempo anchor and produces blocks. The other quorum members are followers: they receive the leader's blocks over an authenticated static P2P network, re-execute and persist them, and sign settlement commitments. The leader collects enough distinct signatures to satisfy the portal's threshold before submitting a batch to Tempo. Each zone also has an independent **admin** authority that holds governance powers (enabling tokens, configuring deposit pause/resume); see [Access Control](#access-control). The admin address may also be assigned a portal role, including `Sequencer`. **Users** deposit TIP-20 tokens from Tempo into the zone, transact privately, and withdraw back to Tempo.

The admin may also schedule permanent abdication of independently controlled portal capabilities.

On the Tempo side, an onchain **verifier** contract validates that each batch was executed correctly. The verifier is abstracted behind a minimal interface (`IVerifier`) and is proof-agnostic. Any proving backend (ZK, TEE, or otherwise) can implement the interface. The portal does not care how the proof was produced.

On Tempo, each zone has a **portal** that locks deposited tokens. All user deposits encrypt the zone recipient and memo to a registered sequencer encryption key. In closed access mode, only allowed accounts may initiate deposits and refund recipients must also be allowed; open access mode skips both membership checks. Decrypted zone recipients need not be allowed Tempo accounts. The portal locks the tokens and appends the deposit to a queue. The sequencer observes the deposit, advances the zone's view of Tempo, and mints equivalent tokens on the zone.

[TIP-1096: Multi-block Tempo Imports for Zones](https://github.com/tempoxyz/tempo/blob/main/tips/tip-1096.md) allows a zone to catch up after downtime without generating historical state proofs for every missed Tempo block. See [Multi-block Tempo Imports](#multi-block-tempo-imports).

Users transact on the zone privately. Balances, transfers, and transaction history are only visible to the account holder and the sequencer nodes. The zone does not post transaction data, and data availability is entrusted to the sequencer fleet. Sequencers have full visibility into zone activity. Privacy protects against public observers on Tempo, not against sequencers.

Zones rely on the following trust assumptions: the verifier must be sound for state transition integrity, the sequencers are trusted for liveness and data availability, and there is no forced inclusion or permissionless exit mechanism.

When a user wants to exit, they request a withdrawal on the zone. Their tokens are burned on the zone side, and the withdrawal is added to a pending list. At the end of a batch, the sequencer finalizes all pending withdrawals into a hash chain and generates a proof covering the full batch of zone blocks. The sequencer submits this batch and proof to the portal on Tempo, which verifies the proof and queues the withdrawals. The sequencer then processes each withdrawal, releasing tokens from the portal to the recipient.

```mermaid
sequenceDiagram
    participant U as User
    participant T as Tempo
    participant Z as Zone

    Note over T: Deposit
    U->>T: ZonePortal.deposit()
    T->>T: lock tokens, append to deposit queue

    Note over Z: Process deposit
    Z-->>T: observe DepositMade
    Z->>Z: ZoneInbox.advanceTempo()
    Z->>Z: mint tokens to recipient

    U->>Z: transact privately

    Note over Z: Withdrawal
    U->>Z: ZoneOutbox.requestWithdrawal()
    Z->>Z: burn tokens, finalize batch

    Note over T: Settlement
    Z->>T: ZonePortal.submitBatch()
    T->>T: verify proof, queue withdrawals

    Note over T: Withdraw
    Z->>T: ZonePortal.processWithdrawals()
    T->>U: release tokens
```

<br>

## Access Control

Each zone has an **admin** authority and a set of **sequencers** registered on the [`ZonePortal`](#izoneportal). They can be operationally separated so mission-critical governance powers remain in a cold key or multisig, but the protocol does not require distinct addresses: admin authority is independent from the mutually exclusive portal role assigned to an address.

### Roles

**Admin.**

- Holds governance powers over the zone (token enablement, deposit pause/resume, and account and gateway membership).
- Can schedule permanent abdication of portal capabilities after a delay.
- Expected to be a cold key, multisig, or governance contract.
- Set at zone creation via [`IZoneFactory.createZone`](#izonefactory).
- Rotatable via a two-step transfer (see [Admin Transfer](#admin-transfer)), so a lost or compromised admin key can be moved to a new cold key or multisig.
- Cannot be renounced.

**Sequencers.**

- Operate the zone as a leader/follower fleet. The active leader collects transactions, produces blocks, advances Tempo, processes deposits and withdrawals, and submits batches with proofs. Followers replicate and validate blocks and sign matching settlement attestations.
- Are configured at creation as a nonempty set of at most eight unique addresses and a nonzero settlement threshold no greater than the set size. The first address is installed as the initial leader.
- May be replaced atomically by the admin together with the threshold. The configuration nonce starts at `0`; each later replacement increments `sequencerSetVersion` and invalidates certificates from earlier configurations.
- Any active sequencer may perform a sequencer-authorized portal operation or submit a batch transaction. In normal node operation, the leader performs these duties, and batch settlement additionally requires a threshold certificate containing distinct active-sequencer signatures.
- Hold the encryption private keys corresponding to the portal's encryption public keys and used to decrypt [deposits](#deposits).

The admin may also be a member of the sequencer set. Admin authorization remains independent of
the account's mutually exclusive portal role.

### Permission Matrix

The following table lists every privileged action and the role authorized to invoke it.

| Action | Contract | Authorized caller |
|---|---|---|
| `enableToken(token)` | [`ZonePortal`](#izoneportal) | **admin** |
| `pauseDeposits(token)` | [`ZonePortal`](#izoneportal) | **admin** |
| `resumeDeposits(token)` | [`ZonePortal`](#izoneportal) | **admin** |
| `pause()` | [`ZonePortal`](#izoneportal) | **admin, sequencer, or pause guardian** |
| `resume()` | [`ZonePortal`](#izoneportal) | **admin** |
| `setAllowedAccount(account, allowed)` | [`ZonePortal`](#izoneportal) | **admin** |
| `setGateway(account, allowed)` | [`ZonePortal`](#izoneportal) | **admin** |
| `setPauseGuardian(account, allowed)` | [`ZonePortal`](#izoneportal) | **admin** |
| `abdicate(capability)` | [`ZonePortal`](#izoneportal) | **admin** |
| `setAccessMode(mode)` | [`ZonePortal`](#izoneportal) | **admin** |
| `setGatewayMode(mode)` | [`ZonePortal`](#izoneportal) | **admin** |
| `transferAdmin(newAdmin)` | [`ZonePortal`](#izoneportal) | **admin** |
| `acceptAdmin()` | [`ZonePortal`](#izoneportal) | **pending admin** |
| `setSequencerSet(sequencers, threshold)` | [`ZonePortal`](#izoneportal) | **admin** |
| `setLeader(newLeader, expectedEpoch)` | [`ZonePortal`](#izoneportal) | **admin or any active sequencer**; `newLeader` must be active |
| `setZoneGasRate(rate)` | [`ZonePortal`](#izoneportal) | **admin** |
| `setMaxTempoGasRate(rate)` | [`ZonePortal`](#izoneportal) | **admin** |
| `setBouncebackGas(gasAmount)` | [`ZonePortal`](#izoneportal) | **admin** |
| `setSequencerEncryptionKey(...)` | [`ZonePortal`](#izoneportal) | **admin or any active sequencer** |
| `setRpcUrl(url)` | [`ZonePortal`](#izoneportal) | **any active sequencer** |
| `submitBatch(...)` | [`ZonePortal`](#izoneportal) | **any active sequencer with a threshold certificate** |
| `processWithdrawals(...)` | [`ZonePortal`](#izoneportal) | **any active sequencer** |
| `advanceTempo(...)` | [`ZoneInbox`](#izoneinbox) (zone-side) | **zone system caller (`address(0)`) only** |
| `advanceTempoHeaders(...)` | [`ZoneInbox`](#izoneinbox) (zone-side) | **zone system caller (`address(0)`) only** |
| `finalizeTempo(headers)` | [`TempoState`](#itempostate) (zone-side) | **`ZoneInbox` only**; static calls are rejected |
| `setTempoGasRate(rate)` | [`ZoneOutbox`](#izoneoutbox) (zone-side) | **sequencer** or zone system caller (`address(0)`) |
| `setMaxWithdrawalsPerBlock(limit)` | [`ZoneOutbox`](#izoneoutbox) (zone-side) | **sequencer** or zone system caller (`address(0)`) |
| `finalizeWithdrawalBatch(...)` | [`ZoneOutbox`](#izoneoutbox) (zone-side) | **zone system caller (`address(0)`) only** |
| Block production / `beneficiary` | zone | **active leader for the block's Tempo anchor** |

Rationale notes:

- **Token enablement and deposit pause/resume are admin-only** because they govern what the zone is and which deposit flows are open. A compromised sequencer hot key MUST NOT be able to enable arbitrary tokens or unilaterally re-open paused deposits.
- **Capability abdication is admin-only** because it permanently removes a Portal configuration surface after the delay.
- **Withdrawal gas rates are sequencer-controlled within an admin ceiling** so the sequencer can react quickly to Tempo gas-price fluctuations while the admin retains control over the maximum user fee. The admin directly controls the Tempo-side deposit and bounce-back fee parameters.
- **Encryption public-key management is admin- or sequencer-authorized**. Both paths require a proof of possession from the corresponding encryption private key, so neither role can register a public key it cannot decrypt with.
- **Zone-side system calls** to `ZoneInbox` and `ZoneOutbox.finalizeWithdrawalBatch` use `msg.sender == address(0)`. Withdrawal finalization is system-only —`TempoState.finalizeTempo` is only callable only by `ZoneInbox`—. Sequencers may call the outbox gas-rate and withdrawal-limit setters directly.
- **Withdrawal processing is sequencer-only** today; whether to make it permissionless once the proof has settled is tracked separately.

<br>

## Zone Deployment

A zone is created via `ZoneFactory.createZone(...)` on Tempo with the following parameters:

| Parameter | Description |
|-----------|-------------|
| `initialToken` | The first TIP-20 token to enable. The admin can enable additional tokens later. |
| `accessMode` | Initial account enforcement flag: `true` requires the `Account` role; `false` skips account membership checks. The admin may change it later. |
| `gatewayMode` | Initial callback enforcement flag: `true` requires the `CallbackGateway` role; `false` accepts arbitrary callback targets. The admin may change it later. |
| `allowedAccounts` | Optional addresses initially assigned the `Account` role. An empty closed configuration denies all accounts until the admin assigns one; open mode may pre-stage roles for a later close. Members MUST NOT be the messenger. |
| `zoneGateways` | Optional addresses initially assigned the `CallbackGateway` role. Gateways MUST NOT also be allowed accounts. Roles are retained while gateway mode is open. |
| `admin` | The nonzero address that holds the admin role for the zone. |
| `sequencers` | One to eight unique, nonzero sequencer addresses. The first address becomes the initial leader; otherwise order has no protocol meaning. |
| `threshold` | The number of distinct active-sequencer signatures required for settlement. MUST be nonzero and no greater than `sequencers.length`. |
| `rpcUrl` | The operator RPC endpoint advertised for the zone. |

The native factory assigns a unique `zoneId`, etches the TIP-1091 proxy runtime at its reserved vanity address, initializes the portal storage with the fixed messenger and verifier, sets `blockHash` and the initial sequencer-set configuration nonce to zero, and enables the initial token. Enabling the initial token also initializes `tokenEnablementHash` from the exact token metadata included in the initial `TokenEnabled` event, using the transition defined in [Token Enablement Commitment](#token-enablement-commitment). The [`ZoneCreated`](#izonefactory) event emits the zone deployment parameters.

Canonical Zone genesis MUST anchor to a finalized Tempo block preceding the block that creates its portal. It MUST leave `ZoneInbox.processedTokenEnablementHash` at zero and replay the portal-creation block, including the initial `TokenEnabled` event. Implementations MUST reject genesis construction at or after portal deployment rather than pre-populating protocol state from a later portal snapshot.

The shared portal runtime MUST preserve the native factory's constructor-equivalent storage suffix:

| Slot | Offset | Value |
|------|-------:|-------|
| 15 | 0 | `zoneId` |
| 15 | 4 | `messenger` |
| 16 | 0 | `verifier` |
| 16 | 20 | `_initialized` |
| 16 | 21 | `sequencerSetVersion` |
| 16 | 29 | `sequencerThreshold` |
| 17 | 0 | `zoneHeight` |
| 18 | 0 | `_sequencers` |
| 19 | 0 | `isSequencer` |
| 20 | 0 | `role` |
| 21 | 0 | `_isAccessEnforced` |
| 21 | 1 | `_isGatewayEnforced` |
| 22 | 0 | `maxTempoGasRate` |
| 23 | 0 | `leader` |
| 23 | 20 | `leaderEpoch` |
| 24 | 0 | `leaderActivationTempoBlock` |
| 24 | 8 | `_depositCountBlock` |
| 24 | 16 | `_depositsInCurrentBlock` |
| 24 | 24 | `_tokenEnableCountBlock` |
| 25 | 0 | `_tokensEnabledInCurrentBlock` |
| 26 | 0 | `tokenEnablementHash` |
| 28 | 0 | `lastProcessedEnabledTokenCount` |

The factory performs this initialization natively in the portal account; the Solidity
`initialize` function documents and tests the equivalent state transition.

### Chain ID

Each zone has a unique chain ID derived from its parent Tempo chain ID and zone ID:

```
if parent_chain_id == 4217:
    chain_id = 421700000 + zone_id       # zone_id < 1002610000
else if parent_chain_id == 42431:
    chain_id = 1424310000 + zone_id      # zone_id < 723173648
else:
    chain_id = (parent_chain_id << 32) | zone_id
    # 0 < parent_chain_id <= 1048574
```

The production ranges reject exhaustion rather than wrapping. Generic IDs are at least `2^32` and cannot collide with the sub-`2^31` production ranges. The generic-parent ceiling ensures that even the largest `zone_id` keeps the EIP-155 legacy signature `v` value below JavaScript's `Number.MAX_SAFE_INTEGER`. Distinct devnets MUST use distinct parent chain IDs. This prevents replay between zones and between mainnet, Moderato, and devnets. The chain ID is set in genesis; the parent and zone IDs decoded from it are validated at startup against the connected parent and the configured `ZonePortal.zoneId()`.

### Tempo Contracts

A single [`ZoneFactory`](#izonefactory) on Tempo creates zones and maintains the registry of all deployed zones. The factory also exposes the shared [`ZoneMessenger`](#izonemessenger) used for withdrawal callbacks. When a zone is created, the factory deploys one per-zone contract:

| Contract | Purpose |
|----------|---------|
| [`ZonePortal`](#izoneportal) | Locks deposited tokens, accepts batch submissions, verifies proofs, and processes withdrawals. Manages the token registry and deposit/withdrawal queues. |

The factory's shared `ZoneMessenger` is fixed when each portal is initialized. It is separated from the portal so callback code does not execute with the fund-owning portal as `msg.sender`. An account has exactly one of `None`, `Sequencer`, `Account`, `CallbackGateway`, or `PauseGuardian`. The admin manages these roles through `setAllowedAccount`, `setGateway`, and `setPauseGuardian`, while sequencer membership changes only through `setSequencerSet`. Each managed-role setter controls only its corresponding role, so changing roles requires first clearing the current role and then assigning the new one. `setAccessMode` and `setGatewayMode` activate or deactivate enforcement of the corresponding roles without clearing them.

Account and gateway membership is evaluated when each portal or zone-side action executes. Revoked in-flight destinations and gateways bounce back, while revoked refund recipients have funds parked until membership is restored.

### Zone Predeploys

Each zone has three system contracts deployed at genesis at fixed addresses:

| Predeploy | Address | Purpose |
|-----------|---------|---------|
| [`TempoState`](#itempostate) | `0x1c00...0000` | Stores the finalized Tempo checkpoint used to anchor the zone's Tempo L1 state view. |
| [`ZoneInbox`](#izoneinbox) | `0x1c00...0001` | Advances the zone's view of Tempo and processes incoming deposits. Sole mint authority. |
| [`ZoneOutbox`](#izoneoutbox) | `0x1c00...0002` | Handles withdrawal requests and batch finalization. Sole burn authority. |

### Zone Token Model

Contract creation is disabled on zones (`CREATE` and `CREATE2` revert). All TIP-20 tokens on a zone are representations of Tempo tokens, deployed at the same address as on Tempo. When the admin enables a token on the portal, `ZoneInbox` directly initializes the corresponding TIP-20 state and bridge roles during `advanceTempo` after authenticating the enablement against Tempo state. The TIP-20 factory is disabled on zones.

Token supply on the zone is controlled exclusively by the system contracts:

- `ZoneInbox` mints tokens when processing deposits from Tempo.
- `ZoneOutbox` burns tokens when users request withdrawals.

The zone-side supply of each token always equals net deposits minus net withdrawals. The corresponding tokens on Tempo are locked in the portal. No other actor can mint or burn zone tokens.

<br>

## Sequencer Operations

### Multi-Sequencer Topology

Zones do not publish transaction data to Tempo, so a single-sequencer deployment would make one node the only durable copy of the zone chain. If this node crashed or its disk became corrupted, the zone could become unrecoverable. Followers independently execute and persist every block, providing redundant copies from which the zone can recover if the leader or its storage is lost. Operators SHOULD place sequencers in separate failure domains so a single machine, network, or storage failure does not eliminate that redundancy.

When the settlement threshold is greater than one, a compromised sequencer's individual settlement key alone cannot certify a batch. Follower sequencers reconstruct the commitment from their own validated state and sign only an exact match.

The sequencer nodes share a TOML manifest supplied with `--sequencer.manifest`. It lists each node's name, network address, Commonware Ed25519 public key, individual secp256k1 settlement address, and optional `rpc_only` status. The Ed25519 key authenticates P2P traffic; the secp256k1 key signs EIP-712 settlement attestations and its address must be registered in the portal's active sequencer set. These keys are independent.

At startup, each node checks that its local keys identify the same manifest member, every quorum member is an active portal sequencer, and `sequencerThreshold` is nonzero and reachable by the manifest quorum. An `rpc_only` node replicates the chain and forwards transactions but has no settlement key, is not a portal sequencer, never signs an attestation, and does not count toward the threshold.

#### RPC-Only Followers

An RPC-only follower is a non-quorum replica intended to be the client-facing RPC endpoint. It imports, validates, and persists the same canonical blocks as the sequencers, applies the same RPC authorization and response-redaction rules, and serves reads from its local state. Transactions submitted to it are admitted to its local pool and forwarded over authenticated P2P to every quorum member, so clients do not need direct network access to the leader or quorum followers.

The manifest marks this role with `rpc_only = true`. The node has a P2P Ed25519 key, but it has no individual secp256k1 settlement key and is not registered in the portal's sequencer set. It also MUST NOT hold the shared sequencer key used for block production and deposit decryption. Consequently, an RPC-only follower cannot produce blocks, become leader, sign a settlement attestation, submit sequencer-authorized portal transactions, or count toward the settlement threshold. Promoting it requires provisioning an individual settlement key, registering that address with the portal, removing `rpc_only` from the manifest, and restarting the node with the quorum-member configuration.

The manifest's `leader_ed25519_public_key` is a bootstrap value. Live leadership comes from the
finalized `ZonePortal.leader`, `leaderEpoch`, and `leaderActivationTempoBlock` state and
`LeaderUpdated` events. Nodes change roles at the corresponding Tempo activation boundary. There
is no automatic election: an admin or active sequencer must call `setLeader`, except during an
explicit operator-configured forced-recovery procedure.

For each zone block, the leader selects transactions, advances the Tempo anchor, executes the
block, persists it, and broadcasts it over P2P. Checkpoint-only blocks contain no user or portal
work; their leader is selected by their first imported Tempo header. Followers accept live blocks
only from the scheduled leader, then execute, validate, canonicalize, and persist the block
locally. They validate checkpoint-only header ranges independently. Missing blocks are recovered
through bounded P2P backfill, and portal work crossed by checkpoint-only blocks remains deferred
until the next block.

At a batch boundary, settlement proceeds as follows:

1. The leader derives the settlement attestation from its persisted chain and portal state, signs
   it with its individual secp256k1 key, and broadcasts the proposal.
2. Each quorum follower independently reconstructs the attestation from its own persisted and
   validated state. It signs only if the full proposal matches, including the sequencer-set
   version, zone height, withdrawal batch index, Tempo anchor, block transition, deposit and
   token-enablement transitions, withdrawal queue hash, verifier, and verifier configuration hash.
3. The leader verifies returned signatures against the authenticated peer identities and the
   manifest's settlement addresses, then waits until one identical attestation has at least
   `sequencerThreshold` distinct signatures, including its own.
4. The leader submits the proof and certificate to `ZonePortal.submitBatch`. The portal recovers
   the signers, requires each signer to be active and unique, and rejects stale, malformed,
   duplicate, or insufficient certificates.

Followers therefore attest to settlement after validating leader-built blocks; they do not
participate in transaction ordering or block production. A threshold of one remains valid, but a
multi-sequencer deployment normally uses a threshold of at least two with three or more quorum
members, so every settled batch includes a follower signature and remains recoverable from a
follower after loss of the leader's disk.

### Token Management

The admin manages which TIP-20 tokens are available on the zone (see [Access Control](#access-control)):

- `enableToken(token)`: Enable a new TIP-20 for deposits and withdrawals. This is **irreversible**. Once enabled, a token can never be disabled.
- `pauseDeposits(token)`: Pause new deposits for a token. Does not affect withdrawals.
- `resumeDeposits(token)`: Resume deposits for a previously paused token.
- `pause()`: Pause all new deposits, Zone withdrawal requests, Zone block production, and L1
  withdrawal processing for the public `PAUSE_DURATION` constant of 30 days. The pause expires
  automatically and cannot be extended while active. The leader stops producing Zone blocks no
  later than the first block anchored at or after the finalized Tempo block that emitted
  `PortalPaused`; a block already being built may finish. Followers do not check the pause and
  import whatever the leader produces. Because automatic expiry emits no event, the leader also
  polls `paused()` at the latest finalized Tempo block, and reads it at startup before producing
  blocks. Proof-verified batch submission for blocks produced before the pause continues. After
  the pause clears, the Zone catches up on the Tempo blocks finalized during the pause. Historical
  catch-up requires an L1 endpoint that serves the missed finalized headers, receipts, and
  anchored state.
- `resume()`: Allow the admin to resume those flows before the bounded pause expires. Resuming
  remains available after `Capability.PausePortal` is abdicated.
- `abdicate(Capability.PausePortal)`: Permanently disable future portal-wide pauses after one
  `ABDICATION_DELAY` (30 days). It does not clear an active pause; any pause started before
  abdication takes effect runs to its own expiry.
- `abdicate(Capability.AccessPolicy)`: Permanently freeze account roles, gateway roles, and
  enforcement modes after the same delay. Existing access roles cannot be revoked afterward.

The portal maintains a `TokenConfig` per token with an `enabled` flag and a configurable `depositsActive` flag, along with an append-only `enabledTokens` list. The admin can halt deposits but cannot disable withdrawals for an enabled token. At most `MAX_UNPROCESSED_TOKEN_ENABLEMENTS` (8) entries may remain enabled on Tempo but unprocessed by an accepted zone batch. This keeps the `advanceTempo()` call within its execution and proof budget even when checkpoint-only blocks defer work across many Tempo blocks. Each metadata string copied into the zone (`name`, `symbol`, and `currency`) is bounded to 31 encoded bytes. Note that token issuers can independently restrict transfers via TIP-403 policies, which may cause withdrawals to fail and bounce back (see [Withdrawal Failures and Bounce-Back](#withdrawal-failures-and-bounce-back)).

### Token Enablement Commitment

`ZonePortal.tokenEnablementHash` is an append-only commitment to every token enabled for the zone and to the exact metadata used to initialize its zone-side TIP-20 representation. Its initial value is zero. For an enabled token `t`, the next commitment is:

```
nextTokenEnablementHash = keccak256(
    abi.encode(
        tokenEnablementHash,
        t.token,
        t.name,
        t.symbol,
        t.currency
    )
)
```

The encoding is Solidity's standard `abi.encode(bytes32,address,string,string,string)` encoding, not packed encoding. Implementations in other languages must produce exactly the same bytes. `ZonePortal` updates `tokenEnablementHash` once in `_enableTokenInternal`, using the same metadata bytes emitted in `TokenEnabled`, and no other operation may modify it. The native `ZoneFactory` performs the identical transition for the initial token when it creates a portal.

`ZoneInbox` stores both `processedTokenEnablementHash` and `processedEnabledTokenCount`. `advanceTempo` starts from the stored hash and applies the transition above to every supplied `enabledTokens` entry in order. It then reads the portal's `tokenEnablementHash` at the imported Tempo root and requires exact equality. A mismatch reverts the complete system transaction before token initialization or deposit processing. Partial token-enablement processing is not permitted.

Consequently, `enabledTokens` is the exact ordered append-only suffix that transforms the prior zone commitment into the portal commitment at the block's imported header. After checkpoint-only blocks, it may contain events from multiple Tempo blocks, always in transaction and log order. After equality is established, `ZoneInbox` initializes every supplied token, grants the Inbox and Outbox bridge roles, updates the hash and processed count, and only then processes deposits. An offchain comparison against observed receipt logs is defense in depth and is not a substitute for this consensus check.

Each batch proof returns a `TokenEnablementTransition` from the inbox's previous processed count to its post-state count. `ZonePortal.submitBatch` requires that transition to be continuous with `lastProcessedEnabledTokenCount`, monotonic, and no greater than `enabledTokenCount`. The hash authenticates the metadata and ordering; the count lets the portal enforce the outstanding-work bound without replaying the hash chain.

### Gas Rate Configuration

The admin configures Tempo-side deposit and bounce-back fees, while sequencers configure the zone-side withdrawal rate. Each rate is the price (in token units) of one gas unit on the chain where the work runs:

| Rate | Set via | Used for |
|------|---------|----------|
| `zoneGasRate` | `ZonePortal.setZoneGasRate()` | Deposit fees: `FIXED_DEPOSIT_GAS (100,000) * zoneGasRate` |
| `maxTempoGasRate` | `ZonePortal.setMaxTempoGasRate()` | Admin ceiling for the sequencer-controlled withdrawal gas rate |
| `tempoGasRate` | `ZoneOutbox.setTempoGasRate()` | Withdrawal fee reserve: `(WITHDRAWAL_BASE_GAS (50,000) + gasLimit) * tempoGasRate` |

`zoneGasRate` and `maxTempoGasRate` live on `ZonePortal` on Tempo. `maxTempoGasRate` defaults to zero, so nonzero withdrawal pricing remains disabled until the admin explicitly configures a ceiling. `tempoGasRate` lives on the zone-side `ZoneOutbox`; the sequencer may update it only to a value less than or equal to the finalized portal maximum. The outbox reads `tempoGasRate` at withdrawal-request time. Deposit and withdrawal fees are snapshotted onto their queued entries, so in-flight rate changes never retroactively raise the fee on already-queued items.

Deposit bounce-backs do not use `tempoGasRate`. Their fee is derived from the admin-configured `bouncebackGas`, Tempo `block.basefee`, and `TEMPO_BASE_FEE_SCALE (1e12)`. All rates are denominated in token units per gas unit and fees are paid in the same token being deposited or withdrawn. Tempo-side deposit and bounce-back fees are paid to the portal admin; the protocol does not distribute them among sequencers.

The sequencer can also configure `maxWithdrawalsPerBlock` via `ZoneOutbox.setMaxWithdrawalsPerBlock(limit)`. This is a zone-side load-shedding limit for withdrawal requests, not a fee parameter. A value of `0` disables the limit.

### Encryption Key Management

The sequencer publishes a secp256k1 encryption public key used for [deposits](#deposits) and for deterministic authenticated-withdrawal sender reveals. The key is set via `setSequencerEncryptionKey(x, yParity, popV, popR, popS)` on the portal, which requires a proof of possession (an ECDSA signature proving control of the corresponding private key).

The portal stores all historical encryption keys in an append-only list. Users specify a `keyIndex` when making encrypted deposits, referencing which key they encrypted to. This avoids a race condition where a key rotates between transaction signing and block inclusion.

When a new key is set, the previous key remains valid for `ENCRYPTION_KEY_GRACE_PERIOD` (86,400 blocks). After that, deposits using the old key are rejected. The current key never expires. Users can call `isEncryptionKeyValid(keyIndex)` before signing to check validity.

### Leadership and Sequencer Set Rotation

The admin atomically replaces the active sequencer set and threshold with `ZonePortal.setSequencerSet(sequencers, threshold)`. Replacement members must be nonzero, unique, and no more than eight; their order has no protocol meaning. The active leader cannot be removed from the set. To replace it, the admin first adds the replacement, transfers leadership, and then removes the previous leader. A replacement increments `sequencerSetVersion`, including a threshold-only change, so certificates collected under the previous configuration cannot be replayed.

The initial configuration uses nonce `0`.

Leadership is transferred with `ZonePortal.setLeader(newLeader, expectedEpoch)`. The new leader must be an active sequencer. `expectedEpoch` provides compare-and-set fencing against stale handoff transactions, and only one distinct leader change is allowed per Tempo block. A real change increments `leaderEpoch`, records the current Tempo block in `leaderActivationTempoBlock`, and emits `LeaderUpdated`; setting the current leader is idempotent. Zone nodes consume this state only after Tempo finalization and authorize block production for the leader scheduled at each block's embedded Tempo anchor.

### Admin Transfer

The admin can transfer the governance role to a new address via the same two-step process, allowing an operator to rotate to a new cold key or multisig after a planned governance change or a suspected key compromise:

1. Current admin calls `ZonePortal.transferAdmin(newAdmin)` to nominate a new admin. Calling it with `address(0)` cancels a pending transfer.
2. New admin calls `ZonePortal.acceptAdmin()` to accept the transfer.

Until `acceptAdmin()` is called the current admin retains all governance powers, so a nomination to a wrong or unreachable address cannot strand the role. Because only a non-zero pending admin can accept, the transfer can never set the admin to `address(0)` — the admin still cannot be renounced.

<br>

## Deposits

Deposits move TIP-20 tokens from Tempo into a zone. The user deposits on Tempo, the portal locks the tokens and appends the deposit to a hash chain, and the sequencer mints equivalent tokens on the zone.

The user-facing deposit ABI is encrypted-only. `deposit(...)` is an exact alias of `depositEncrypted(...)` with the same encrypted arguments, validation, queue encoding, and `DepositMade` event; first-party clients use `deposit`. `DepositType.WithdrawalBounceBack` remains solely as the internal encoding for withdrawal bounce-backs. This is a breaking protocol boundary: zones created against a plaintext-deposit implementation are not migrated or backfilled and must be recreated.

### Deposit Fees

Every deposit is associated with a deposit fee and a possible bounce-back fee:

```
depositFee    = FIXED_DEPOSIT_GAS    * zoneGasRate    (= 100,000 * zoneGasRate)
bouncebackFee = ceil(bouncebackGas * block.basefee / 1e12)
```

The deposit fee is charged on every deposit and paid immediately. The bounce-back fee is not stored on the deposit; it is recalculated from Tempo's current `block.basefee` only if the deposit actually bounces back.

The two fees are conceptually independent because their work happens on different chains:

- The **deposit fee** covers the operational cost of processing the deposit on the zone (calling `advanceTempo`, performing the mint, advancing the queue) and is therefore priced at the zone's gas rate. It is charged on every deposit, success or failure, and paid to the portal admin immediately on Tempo.
- The **bounce-back fee** covers the worst-case Tempo-side cost of paying out a refund — primarily new-account creation for `tempoRefundRecipient`, which can dominate the gas of `processWithdrawals` and is much larger than the steady-state per-deposit gas — and is priced from Tempo `block.basefee`. It is charged only when a deposit actually bounces back, and is paid to the portal admin at that point.

### Deposit Queue

Deposits flow from Tempo to the zone through a hash chain. The portal tracks a single `currentDepositQueueHash` representing the head of the chain. Each new deposit wraps the existing hash:

```
currentDepositQueueHash = keccak256(abi.encode(DepositType.Deposit, deposit, currentDepositQueueHash))
```

The newest deposit is always outermost, making onchain addition O(1). The zone tracks its own `processedDepositQueueHash` and `processedDepositNumber` in state. During `advanceTempo()`, the zone processes deposits oldest-first, rebuilding the hash chain and validating that the result matches `currentDepositQueueHash` read from Tempo L1 at the zone's finalized checkpoint.

At most `MAX_UNPROCESSED_DEPOSITS` (230) entries may remain queued on the portal but unprocessed by an accepted zone batch. The bound covers encrypted deposits and internal withdrawal bounce-backs because both use the same queue. Public deposits normally stop at 210 outstanding entries, reserving 20 slots for one maximum-size withdrawal batch to bounce back; one guarded withdrawal callback may consume a reserved slot when returning value through a deposit. The global bound keeps the complete deferred deposit suffix within the zone's `advanceTempo()` execution and proof budget and guarantees withdrawal progress under sustained public deposit load.

`advanceTempo()` reads the portal's `currentDepositQueueHash` from Tempo L1 at the zone's finalized checkpoint. The call must process deposits through the current queue head: after rebuilding the hash chain, the resulting `processedDepositQueueHash` must equal the portal's `currentDepositQueueHash`.

After a batch is accepted, the portal updates `lastSyncedTempoBlockNumber` to record how far Tempo state was synced, and updates `lastProcessedDepositNumber` from the proven `DepositQueueTransition`. Users should track deposit inclusion by deposit number: `DepositMade` emits `depositNumber`, `ZoneInbox.TempoAdvanced` emits the inbox's `lastProcessedDepositNumber`, and `ZonePortal.BatchSubmitted` emits the accepted portal value. A deposit with number `N` is processed once `lastProcessedDepositNumber >= N`.

### Deposits

Users can encrypt the recipient and memo of a deposit so that only the sequencer can see who received the funds. The token, sender, and amount remain public (required for onchain accounting), but the `to` address and `memo` are encrypted.

The encryption scheme is ECIES with secp256k1:

1. The user generates an ephemeral keypair and derives a shared secret via ECDH with the sequencer's published encryption key.
2. The user derives an AES-256 key from the shared secret and the deposit sender using HKDF-SHA256.
3. The user encrypts `(to || memo || padding)` with AES-256-GCM, producing ciphertext, a nonce, and an authentication tag.
4. The user calls `deposit(token, amount, keyIndex, encryptedPayload, tempoRefundRecipient)` on the portal, where `keyIndex` references which encryption key they encrypted to (see [Encryption Key Management](#encryption-key-management)), and `tempoRefundRecipient` is the Tempo address that receives a refund if zone-side processing fails (see [Deposit Failures and Bounce-Back](#deposit-failures-and-bounce-back)). In closed access mode, the caller and refund recipient must be allowed; a caller with the `CallbackGateway` role is the exception while gateway mode is enforced. Open access mode skips membership checks. The decrypted `to` address is not checked against Tempo membership. `deposit` also enforces its fee, encryption-key, payload-shape, and TIP-403 checks.

Before queue insertion, the portal also validates encrypted-payload shape. `deposit` reverts `InvalidEphemeralPubkey` if the ephemeral public key parity is not `0x02` or `0x03`, or if the X coordinate is not a valid secp256k1 X coordinate. It reverts `InvalidCiphertextLength(actual, expected)` unless `ciphertext.length == 64`, the fixed plaintext size for `(to, memo, padding)`. These are Tempo-side deposit-time reverts: no queue entry is created and no zone-side bounce-back is needed.

The portal locks the tokens, appends the encrypted deposit to the deposit queue, and emits `DepositMade`, including `tempoRefundRecipient`. The sequencer provides the ECDH shared secret and proof when processing the deposit on the zone via `advanceTempo()`; the zone decrypts `(to, memo)` from the ciphertext onchain.

Encrypted user deposits and internal withdrawal bounce-backs share a single ordered queue with a type discriminator in the hash:

```
keccak256(abi.encode(DepositType.WithdrawalBounceBack, deposit, prevHash))
keccak256(abi.encode(DepositType.Deposit, deposit, prevHash))
```

`DepositType.WithdrawalBounceBack` is reserved for portal-created withdrawal bounce-backs; it is not a user deposit API. Entries are processed in their exact queue order.

| Field | Visibility | Reason |
|-------|------------|--------|
| `token` | Public | Required for onchain accounting and zone-side minting |
| `sender` | Public | Required for onchain accounting and as the origin of the deposit event |
| `amount` | Public | Required for onchain accounting |
| `tempoRefundRecipient` | Public | Required; receives the Tempo-side refund if decryption or the final mint fails |
| `to` | Encrypted | Only the sequencer learns the recipient |
| `memo` | Encrypted | Only the sequencer learns the payment context |

### Onchain Decryption Verification

When the sequencer processes an encrypted deposit on the zone, the zone recovers the recipient and memo from the ciphertext onchain without the sequencer revealing their private key or supplying the plaintext.

The sequencer provides the ECDH shared secret alongside a proof of its correct derivation. Verification proceeds in two steps:

1. **Chaum-Pedersen proof.** The sequencer provides a zero-knowledge proof that the shared secret was correctly derived: "I know `privSeq` such that `pubSeq = privSeq * G` AND `sharedSecretPoint = privSeq * ephemeralPub`." The native inbox checks this proof using its [Chaum-Pedersen verifier](#chaum-pedersen-verification). The sequencer's public key is looked up from the onchain key history, not supplied by the sequencer, preventing key substitution.

2. **AES-GCM decryption.** The native inbox derives an AES-256 key from the shared secret using HKDF-SHA256. The HKDF info string includes `tempoPortal`, `keyIndex`, `ephemeralPubkeyX`, and the public deposit `sender` for domain separation. It then performs [AES-GCM decryption](#aes-gcm-decryption) and validates the authentication tag. The plaintext is packed as `[address (20 bytes)][memo (32 bytes)][padding (12 bytes)]` totaling 64 bytes; the zone parses `(to, memo)` directly from it and uses those values for the mint. Binding the sender means replaying a payload from another account derives a different AES key and fails authentication, causing the deposit to bounce back instead of minting to the hidden recipient.

If any step fails (invalid proof, GCM tag mismatch, or invalid decrypted plaintext length), the zone does **not** attempt any zone-side mint. Instead, the deposit bounces back immediately to `tempoRefundRecipient` on Tempo via the outbox (see [Deposit Failures and Bounce-Back](#deposit-failures-and-bounce-back)). Because `deposit` requires a non-zero `tempoRefundRecipient` at deposit time, this path always has a well-defined target and never stalls the deposit queue. Because `(to, memo)` are derived from the decrypted plaintext rather than supplied by the sequencer, there is no separate plaintext-mismatch check and the sequencer cannot redirect a valid ciphertext to a different recipient onchain.

Every encrypted deposit must be processed with exactly one `DecryptionData` entry, consumed in deposit order. The inbox always performs the Chaum-Pedersen and AES-GCM verification; missing or extra decryption entries make `advanceTempo()` revert. There is no sequencer-supplied accept/reject decision.

The Chaum-Pedersen proof also prevents griefing. Without it, a user could submit garbage ciphertext that the sequencer cannot decrypt and cannot prove invalid, blocking the chain. The proof lets the sequencer demonstrate correct shared secret derivation, and the GCM tag failure then proves the ciphertext itself was invalid.

```mermaid
sequenceDiagram
    participant U as User
    participant T as Tempo
    participant Z as Zone

    U->>T: ZonePortal.deposit(..., tempoRefundRecipient)
    Note over T: require tempoRefundRecipient != address(0)
    T->>T: append to depositQueue
    Note over T: emit DepositMade
    Z-->>T: observe DepositMade
    Z->>Z: ZoneInbox.advanceTempo(..., QueuedDeposit)
    Z->>Z: onchain decryption (Chaum-Pedersen + AES-GCM)
    alt verification succeeds
        Z->>Z: try TIP20.mint(decryptedTo, amount)
        alt mint succeeds
            Note over Z: emit DepositProcessed
        else mint reverts (including TIP-403)
            Z->>T: bounce back to tempoRefundRecipient via withdrawal queue
            Note over Z: emit DepositFailed
        end
    else verification fails
        Note over Z: no zone-side mint attempted
        Z->>T: bounce back to tempoRefundRecipient via withdrawal queue
        Note over Z: emit DepositFailed
    end
```

### Deposit Failures and Bounce-Back

Deposits can fail because the zone-side mint reverts (including a TIP-403 policy rejection) or because onchain decryption verification fails. To make sure that all cases can be handled without loss of user funds, every user deposit carries a `tempoRefundRecipient`: a Tempo address that receives a refund if zone-side processing fails. Every encrypted deposit is verified and attempts its mint only when decryption succeeds.

**Validation at deposit time.** `deposit(...)` requires an allowed, non-zero `tempoRefundRecipient` and requires it to be authorized by the token's TIP-403 recipient policy. Zone recipients are not checked against closed-loop membership because they are encrypted. If the on-Tempo refund transfer later reverts because policy changed, the funds are parked in a per-recipient refund registry on the portal and may be claimed only by that allowed recipient via `claimRefund(token)`.

**Triggering conditions.** There are two triggering sites:

- **Encrypted deposit.** Two failure modes, both of which unconditionally bounce back (no zone-side mint is attempted as a fallback):
  - **Invalid encryption.** The Chaum-Pedersen proof, AES-GCM tag, or decrypted plaintext length check fails during [Onchain Decryption Verification](#onchain-decryption-verification). There is no well-defined recipient on the zone in this case, so the zone does not try to mint to the depositor; it bounces back immediately.
  - **Valid decryption, mint reverts.** `TIP20.mint(decryptedTo, amount)` reverts (for example, because a TIP-403 policy active on the zone forbids minting to the decrypted recipient, or a custom TIP-20 `mint` reverts for some token-specific reason). The deposit bounces back.

Because the deposit entry point requires a non-zero `tempoRefundRecipient`, every user-initiated deposit has a refund target and the deposit queue never stalls on a failed mint or invalid encryption.

The portal's internal withdrawal-bounce-back deposits are the only `DepositType.WithdrawalBounceBack` entries. Their canonical payload contains only `token`, the fallback nonce encoded in `to`, and `amount`. They are introduced by `_enqueueWithdrawalBounceBack` after a withdrawal callback fails, and their zone-side mint failure path is the symmetric refund-registry described in [Withdrawal Failures and Bounce-Back](#withdrawal-failures-and-bounce-back), preserving the terminal-bounce invariant.


**Zone-side handling.** When an encrypted deposit fails, the `ZoneInbox` calls `ZoneOutbox.enqueueDepositBounceBack(token, amount, tempoRefundRecipient)`. Invalid encryption skips the mint, and a mint revert is caught. `enqueueDepositBounceBack` records a zero-callback, zero-`fallbackNonce` withdrawal in the outbox's pending list with `sender = address(0)` and `txHash = bytes32(0)`. The inbox emits `DepositFailed`, the deposit queue hash chain advances normally, and no retries are performed on the zone.


**Tempo-side refund.** The bounce-back withdrawal is submitted in the next batch alongside any user-initiated withdrawals. When `ZonePortal.processWithdrawals` runs on the deposit-bounce-back entry (`gasLimit == 0`, `fallbackNonce == 0`), it computes `bouncebackFee = min(ceil(bouncebackGas * block.basefee / 1e12), amount)` and attempts to pay it to the portal admin. The effective `collectedFee` is `bouncebackFee` only when that transfer succeeds, otherwise it is zero; the portal then attempts to deliver `amount - collectedFee` from its escrow, wrapped in `try/catch`. Before delivery, the portal validates the recipient's TIP-1028 receive policy using the portal as the transfer sender; a blocked policy is treated as failed delivery without invoking TIP-20, so funds cannot be redirected to `ReceivePolicyGuard`.

If the refund transfer succeeds, the portal emits `DepositBounceBack(tempoRefundRecipient, token, amount - collectedFee, collectedFee)`. If it reverts (e.g. the token's TIP-403 policy forbids `tempoRefundRecipient`, or the token is paused), the funds stay in the portal's locked balance and the portal credits `_refunds[token][tempoRefundRecipient] += (amount - collectedFee)` and emits `DepositBounceBackPending(...)`. Either way the bounce-back entry is fully retired. If the admin fee transfer fails, processing continues without charging the fee and the full amount remains refundable.

In the case of a failed bounceback, the recipient can claim the parked funds by calling `ZonePortal.claimRefund(token)` on Tempo. The portal zeroes `_refunds[token][msg.sender]` and attempts direct delivery with the same TIP-1028 precheck; on success it emits `RefundClaimed(msg.sender, token, amount)`, while a blocked policy, false return, or revert leaves storage unchanged so the user can retry later.

- A deposit created by the portal as a bounce-back from a failed _withdrawal_ (`_enqueueWithdrawalBounceBack`) is encoded as the only valid `DepositType.WithdrawalBounceBack` entry with the canonical `(token, to, amount)` payload. The zone-side mint is attempted with the standard `mint`, and on failure the funds land in a refund registry on `ZoneInbox` (see [Withdrawal Failures and Bounce-Back](#withdrawal-failures-and-bounce-back)) rather than re-bouncing.
- A withdrawal created by the zone as a bounce-back from a failed _deposit_ (`enqueueDepositBounceBack`) always sets `gasLimit = 0`, `callbackData = ""`, and `fallbackNonce = 0`. The Tempo-side fee transfer and refund transfer are wrapped in `try/catch`: the portal admin receives `bouncebackFee` only if the fee transfer succeeds, and the user receives `amount - collectedFee` directly only if the refund transfer succeeds. If the fee transfer fails, `collectedFee` is zero and the full amount remains refundable. If the refund transfer fails, the effective refund amount is parked in the portal's refund registry. `bouncebackFee` is computed on Tempo at processing time from `block.basefee` and capped at `amount`.

**Events summary.**

| Event | Emitted by | When |
|-------|------------|------|
| `DepositFailed` | `ZoneInbox` | Encrypted deposit failed — either invalid encryption, or valid decryption with a mint that reverted; funds queued for bounce-back |
| `DepositBounceBack` | `ZonePortal` | Bounce-back withdrawal processed on Tempo and the refund transfer to `tempoRefundRecipient` succeeded |
| `DepositBounceBackPending` | `ZonePortal` | Bounce-back transfer reverted on Tempo (e.g. TIP-403 forbids `tempoRefundRecipient`); funds parked in the portal's refund registry, claimable via `claimRefund(token)` |
| `RefundClaimed` | `ZonePortal` | Recipient claimed an outstanding deposit-bounce-back refund |
| `WithdrawalBounceBack` | `ZonePortal` | Withdrawal-side bounce-back processed on Tempo (zone-side refund mint will be attempted by the inbox; renamed from `BounceBack` for symmetry with `DepositBounceBack`) |

```mermaid
sequenceDiagram
    participant U as User
    participant T as Tempo
    participant Z as Zone

    U->>T: ZonePortal.deposit(..., tempoRefundRecipient)
    Note over T: require tempoRefundRecipient != address(0)
    T->>T: append to depositQueue
    Note over T: emit DepositMade
    Z-->>T: observe DepositMade
    Z->>Z: ZoneInbox.advanceTempo(..., QueuedDeposit)
    Z->>Z: verify/decrypt, then try TIP20.mint(decryptedTo, amount)
    alt mint succeeds
        Note over Z: emit DepositProcessed
    else mint reverts (including TIP-403)
        Z->>Z: ZoneOutbox.enqueueDepositBounceBack()
        Note over Z: emit DepositFailed
    end
    Z->>T: ZoneOutbox.finalizeWithdrawalBatch + submitBatch
    T->>T: ZonePortal.processWithdrawals (zero-callback)
    T->>T: attempt to pay bouncebackFee to admin
    alt fee transfer succeeds
        T->>T: collectedFee = bouncebackFee
    else fee transfer fails
        T->>T: collectedFee = 0
    end
    alt TIP20.transfer(tempoRefundRecipient, amount-collectedFee) succeeds
        T->>U: receives amount-collectedFee
        Note over T: emit DepositBounceBack
    else transfer reverts (e.g. TIP-403)
        T->>T: _refunds[token][tempoRefundRecipient] += amount-collectedFee
        Note over T: emit DepositBounceBackPending
        U->>T: later: ZonePortal.claimRefund(token)
        T->>U: TIP20.transfer(msg.sender, claimed)
        Note over T: emit RefundClaimed
    end
```

<br>

## Withdrawals

Withdrawals move tokens from a zone back to Tempo. The user requests a withdrawal on the zone, tokens are burned, and the sequencer eventually processes the withdrawal on Tempo, releasing tokens from the portal.

```mermaid
flowchart LR
    subgraph Tempo
        P["ZonePortal<br/>escrow"]
        TD["Tempo destination<br/>allowed account or gateway"]
        TR["tempoRefundRecipient<br/>allowed Tempo account"]
        PR["Portal refund ledger<br/>parked while revoked"]
    end

    subgraph Zone
        O["ZoneOutbox"]
        I["ZoneInbox"]
        ZD["Zone deposit recipient<br/>no closed-loop check"]
        ZF["zoneFallbackRecipient<br/>any non-zero Zone address"]
    end

    O -->|withdrawal request| P
    P -->|successful withdrawal| TD
    P -. failed withdrawal .-> I
    I -->|mint bounce-back| ZF

    P -->|deposit| I
    I -->|successful deposit| ZD
    I -. failed deposit .-> O
    O -. queue refund .-> P
    P -->|allowed refund| TR
    P -. revoked recipient .-> PR
    PR -->|claim after membership restored| TR
```

### Withdrawal Request

A user withdraws by calling `requestWithdrawal(token, to, amount, memo, gasLimit, zoneFallbackRecipient, data, revealTo)` on the `ZoneOutbox`. The user must first approve the outbox to spend `amount + fee` of the token, and `amount` must be non-zero. The token must be enabled, and the `zoneFallbackRecipient` must be non-zero but need not be a Tempo allowed account. For a plain withdrawal (`gasLimit == 0`), closed access mode requires `to` to have the `Account` role; open access mode does not. Enforced gateway mode prevents accounts with the `CallbackGateway` role from receiving plain withdrawals and requires callback targets (`gasLimit > 0`) to have that role. Open gateway mode skips both role checks.

Withdrawal requests are bounded before they enter the pending queue. `gasLimit` must be less than or equal to `MAX_WITHDRAWAL_GAS_LIMIT` or the request reverts with `GasLimitTooHigh`; `data.length` must be less than or equal to `MAX_CALLBACK_DATA_SIZE` (1,024 bytes) or the request reverts with `CallbackDataTooLarge`; and `revealTo`, when non-empty, must be a valid 33-byte compressed secp256k1 public key or the request reverts with `InvalidRevealTo`. The Zone EVM supplies the current transaction hash directly to the native outbox; if it is zero, the request reverts with `InvalidCurrentTxHash`, because the transaction hash is part of the authenticated-withdrawal sender tag.

The sequencer can additionally configure `maxWithdrawalsPerBlock` on the outbox. A value of `0` means unlimited. When nonzero, only that many `requestWithdrawal` calls can be accepted in a single zone block; further requests in the same block revert with `TooManyWithdrawalsThisBlock` before any token transfer or burn. The outbox tracks the last block number counted and resets the per-block counter when `block.number` changes.

Before transferring or burning tokens, the outbox reads the packed pause expiry from the portal at the latest finalized Tempo checkpoint. An active pause reverts the request with `PortalIsPaused`. Otherwise the outbox transfers `amount + fee` from the user via `transferFrom`, burns the tokens, assigns a monotonically increasing nonzero `uint64 fallbackNonce`, stores `fallbackNonce -> zoneFallbackRecipient`, and stores the withdrawal in a pending array. The `WithdrawalRequested` event is emitted with the plaintext sender and fallback nonce (zone events are private).

Keeping the recipient in zone state prevents the L1-visible withdrawal and any later bounce-back from revealing the user's private zone address. A monotonic nonce is deterministic under the zone's canonical transaction ordering, including multi-sequencer execution, while remaining collision-free; it reveals only relative withdrawal order and count, not the mapped recipient.

### Withdrawal Fees

The withdrawal fee reserves value against Tempo-side gas costs:

```
fee = (WITHDRAWAL_BASE_GAS + gasLimit) * tempoGasRate
    = (50,000 + gasLimit) * tempoGasRate
```

`WITHDRAWAL_BASE_GAS` (50,000) covers the fixed overhead of processing a withdrawal on Tempo (queue dequeue, transfer, event emission). The user specifies `gasLimit` covering any additional Tempo callback gas. `gasLimit` must be at most `MAX_WITHDRAWAL_GAS_LIMIT` (10,000,000), which keeps the outer `processWithdrawals` transaction below the Tempo L1 block gas limit after portal overhead is added. For simple withdrawals with no callback, use `gasLimit = 0`. The fee is charged in the same token being withdrawn and burned with the withdrawal amount on the zone. It is not included in the cross-chain `Withdrawal` data and the portal does not transfer it from escrow. On success, `amount` goes to the recipient. Failed plain transfers and callbacks re-deposit `amount` using `fallbackNonce`.

`tempoGasRate` lives on the zone-side `ZoneOutbox` (see [Gas Rate Configuration](#gas-rate-configuration)). The outbox reads it at request time and snapshots it onto the queued withdrawal.

### Withdrawal Batching

A withdrawal batch ends with exactly one call to `finalizeWithdrawalBatch(count, blockNumber, encryptedSenders)` on the `ZoneOutbox` in the final block of that batch. The block builder includes this as the last transaction using the zone system caller (`msg.sender == address(0)`), and the `blockNumber` argument must match the current zone block number. The encrypted-senders array carries one sequencer-supplied ciphertext per finalized withdrawal for [authenticated withdrawals](#authenticated-withdrawals) (empty bytes for withdrawals without `revealTo`); `senderTag` is recomputed by the outbox from the queued withdrawal sender, transaction hash, and fallback nonce. This constructs a hash chain from pending withdrawals in LIFO order (newest to oldest), so the oldest withdrawal ends up outermost, enabling FIFO processing on Tempo:

```
withdrawalQueueHash = 0
for i from (count - 1) down to 0:
    withdrawalQueueHash = keccak256(abi.encode(withdrawals[i], withdrawalQueueHash))
```

The function writes `withdrawalQueueHash` and `withdrawalBatchIndex` to `lastBatch` storage, where the proof reads them. The call is required at each batch boundary even if there are zero withdrawals (use `count = 0`) so the batch index advances. The `withdrawalBatchIndex` ensures batches are submitted in order, preventing the sequencer from omitting batches that contain withdrawals.

A successful call emits `BatchFinalized(withdrawalQueueHash, withdrawalBatchIndex)`. This event is the authoritative zone-side batch boundary consumed by the sequencer; “finalized” means sealed on the zone and does not imply that the batch has been submitted to or accepted by Tempo. Acceptance on Tempo is indicated separately by the portal's `BatchSubmitted` event. For an empty batch, `withdrawalQueueHash` is zero while `withdrawalBatchIndex` still advances.

Batch cadence is deterministic, and only a full `advanceTempo` block can close a batch. A full block closes the batch when it processes deposits, when it contains pending withdrawals, when its zone block number is a multiple of the configured interval, or when it follows a nonempty prefix of checkpoint-only blocks. Settling deposit-only batches advances the portal's processed-deposit cursor and reopens deposit capacity without waiting for withdrawals or the interval. The shared block executor, including STF replay, rejects a post-T13 block whose `TempoAdvanced.depositsProcessed` is nonzero without same-block finalization; legacy pre-T13 blocks retain their previous validity rules. The default interval is 120 zone blocks (~1 minute at Tempo's expected 500 ms block interval). A checkpoint-only block never closes a batch, even when its number is an interval multiple; the following block closes it instead. Other intermediate zone blocks do not call `finalizeWithdrawalBatch`.

### Withdrawal Queue

The portal stores withdrawals in an unbounded FIFO. Each batch with a non-zero `withdrawalQueueHash` gets its own logical queue index. Empty batches advance `withdrawalBatchIndex` but do not consume a queue index.

The portal tracks `head` (oldest unprocessed batch) and `tail` (the logical index assigned to the next non-empty batch). Both are monotonically increasing counters that never wrap. Each logical index is used directly as the key in the queue's storage mapping, and `withdrawalQueueSlot(queueIndex)` reads that key. Exhausted slots are deleted. Under TIP-1060, each deletion earns the portal a storage credit that can offset a later queue-slot creation; only growth beyond the queue's previous high-water storage footprint requires net-new storage.

When `submitBatch` includes a non-zero `withdrawalQueueHash`, the current `tail` is assigned as its logical `withdrawalQueueIndex`, the hash is written to `slots[withdrawalQueueIndex]`, and `tail` advances. `BatchSubmitted.withdrawalQueueIndex` emits that assigned logical index. For an empty batch, the event emits `NO_QUEUE_INDEX = type(uint256).max` and `tail` does not advance. Queue capacity cannot prevent a valid batch from acknowledging processed deposits.

### Withdrawal Processing

The sequencer processes ordered withdrawals atomically on Tempo by calling `processWithdrawals(withdrawals, remainingQueue)` on the portal. `remainingQueue` is the queue suffix after the last supplied withdrawal, or `0x00` when the call exhausts the current slot. The portal derives each intermediate queue hash by folding the withdrawals backward from that suffix, then verifies and processes them in order.

Before each call, the portal bounds the attempted withdrawal count by the outstanding deposit-queue capacity. Specifically, with `unprocessed = depositCount - lastProcessedDepositNumber` and `remainingCapacity = MAX_UNPROCESSED_DEPOSITS - unprocessed`, the call requires `unprocessed <= MAX_UNPROCESSED_DEPOSITS` and `withdrawals.length <= remainingCapacity`. This conservative check assumes every attempted withdrawal fails and creates a bounce-back, so all possible side effects fit within the global outstanding-deposit limit. Public deposits cannot consume the reserved 20 entries, and the sequencer admits at most that reserve per withdrawal submission, preventing a public deposit landing after its headroom read from invalidating the call. A finalized withdrawal batch may be split across multiple ordered calls, each carrying the appropriate `remainingQueue`; if capacity is exhausted, an operational Zone batch must process and settle queued deposits before withdrawal delivery resumes.

The portal dequeues before executing the withdrawal, then independently requires `withdrawal.token` to be enabled. Failed callbacks roll back in an external self-call and become bounce-backs, so the dequeue remains committed and cannot block the FIFO. If `remainingQueue` is zero (last item in the slot), processing deletes the slot and advances `head`; otherwise it updates the slot to `remainingQueue`.

The sequencer first packs withdrawals into transactions using a configurable per-transaction gas budget, then submits them through a queue bounded by transaction count. Transactions use consecutive nonces on the dedicated withdrawal nonce key, preserving FIFO queue transitions even when later transactions are broadcast before earlier receipts arrive. If a submission reverts or cannot be confirmed, the sequencer stops admitting new transactions, drains those already submitted, then reconciles the on-chain queue and retries its unfinished suffix.

For a plain withdrawal (`gasLimit == 0`), the portal rechecks the current modes and roles before transferring directly. A failed transfer or a destination invalidated by a mode or membership change creates a withdrawal bounce-back deposit for the Zone-local `zoneFallbackRecipient`.

### Withdrawal Callbacks

For withdrawals with `gasLimit > 0`, enforced gateway mode requires `to` to have the portal's `CallbackGateway` role; open gateway mode accepts any target. The withdrawal queue hash is verified and dequeued by `ZonePortal.processWithdrawal` before the callback reaches the messenger. The portal snapshots `currentDepositQueueHash`, transfers exactly `amount` to its fixed `ZoneMessenger`, and asks the messenger to relay the callback. The messenger authenticates the source portal through `ZoneFactory`, independently applies the current gateway mode and role check, transfers the funds to the target, invokes `onWithdrawalReceived`, and requires the expected selector.

Receiving contracts must implement `IWithdrawalReceiver` and return `onWithdrawalReceived.selector` to confirm successful handling. Receivers authenticate the call by checking `msg.sender == ZONE_MESSENGER_ADDRESS` and can use the `sourcePortal` callback argument to identify the originating portal.

A callback target is untrusted, so the messenger reads at most the single word a `bytes4` return occupies and discards a failing callback's revert data instead of propagating it. Copying an oversized response or revert blob would charge quadratic memory-expansion gas to the messenger and to the portal's delivery frame, letting one withdrawal consume far more than the `gasLimit` it declared and priced under `WITHDRAWAL_BASE_GAS`, and thereby starve the remaining items in a `processWithdrawals` batch. Bounding the copy keeps realized delivery cost within `gasLimit` plus fixed overhead, which is what the block-gas-limit headroom above and the sequencer's batch planner both assume.

Closed access mode requires `currentDepositQueueHash` to change, proving only that some deposit was synchronously appended to the source zone. It does not bind that deposit to the callback's token, amount, or recipient; an enforced gateway is trusted to constrain the operation and return the intended result. Open access mode imposes no source-deposit invariant: callback value may enter another zone or leave the zone system entirely. Any callback failure rolls back the self-call and enqueues a bounce-back while advancing the withdrawal FIFO.

Callback data is opaque to the zone protocol. In enforced gateway mode, accounts with the `CallbackGateway` role are trusted to constrain callback behavior. In open gateway mode, arbitrary callback targets are permitted and no gateway-specific trust assumption is imposed by the protocol.

An over-limit callback withdrawal also bounces back and advances the queue.

For closed access mode, a successful callback must synchronously append a deposit to the source zone, subject to the limitation above. Open access mode deliberately permits arbitrary open-loop routing, including callbacks that deposit into another zone or do not deposit into any zone. The reference implementation contains only test routing implementations; production gateway/vault token-conversion behavior is outside this repository.

### Withdrawal Failures and Bounce-Back

Plain withdrawals can fail on the Tempo side for reasons such as:

- TIP-403 policy restricts the portal or `withdrawal.to`
- The token is paused
- The direct token transfer reverts or returns false

To make sure that all of these cases can be handled without loss of user funds, every user withdrawal carries a nonzero `fallbackNonce`. `ZoneOutbox` privately maps that nonce to the zone address that receives a refund mint if Tempo-side processing fails.

**Validation at withdrawal request time.** `requestWithdrawal(...)` requires a non-zero `zoneFallbackRecipient`; it does not apply Tempo closed-loop membership to that Zone address. In closed access mode, a plain `to` must have the `Account` role. In enforced gateway mode, a plain `to` must not have the `CallbackGateway` role and a callback `to` must have it. Open modes make their corresponding checks inactive.

**Triggering conditions.** A failed plain transfer or callback causes `ZonePortal` to enqueue a bounce-back. This constructs an internal `WithdrawalBounceBackDeposit` with `to = address(uint160(fallbackNonce))` and appends it to the deposit queue:

```
currentDepositQueueHash = keccak256(abi.encode(DepositType.WithdrawalBounceBack, bounceBackDeposit, currentDepositQueueHash))
```

**Zone-side handling.** The next time the sequencer calls `ZoneInbox.advanceTempo`, the inbox sees a `WithdrawalBounceBack` entry, decodes `fallbackNonce` from `to`, and calls `ZoneOutbox.consumeFallbackRecipient(fallbackNonce)`. The outbox returns and deletes the mapped recipient, after which the inbox attempts `IZoneToken.mint(zoneFallbackRecipient, amount)` wrapped in `try/catch`.

If the mint succeeds, the inbox emits `WithdrawalBounceBackProcessed(zoneFallbackRecipient, token, amount)`. If it reverts, the inbox credits the Zone-local refund registry and emits `WithdrawalBounceBackPending(...)`. Either way the bounce-back deposit is fully retired.

The parked balance is exposed through `ZoneInbox.refunds(token, owner)`, which requires its immediate `msg.sender` to equal `owner` or belong to the active sequencer set. Enforcing this at the getter prevents call-forwarding contracts from exposing another account's refund balance. Owners and sequencers must query the getter directly rather than through a multicall contract.

The recipient claims the parked funds by calling `ZoneInbox.claimRefund(token)`. The inbox zeroes `_refunds[token][msg.sender]` and calls `IZoneToken.mint(msg.sender, amount)`; on success it emits `RefundClaimed(msg.sender, token, amount)`, on revert storage is unchanged and the user retries later.

The withdrawal fee is burned on the zone regardless of whether the withdrawal succeeds on Tempo or bounces back.

### Authenticated Withdrawals

Zone transactions are private, but when a withdrawal is processed on Tempo, the `Withdrawal` struct is passed in calldata and publicly visible. To avoid leaking the sender's identity, the `sender` field is replaced with a `senderTag` commitment:

```
senderTag = keccak256(abi.encodePacked(sender, txHash, fallbackNonce))
```

The `txHash` is the hash of the `requestWithdrawal` transaction on the zone. Since zone transaction data is not published, `txHash` acts as a blinding factor known only to the sender and the sequencer. `fallbackNonce` is the public, monotonically increasing identifier already assigned to each user withdrawal. Including it prevents multiple withdrawals from the same private transaction from sharing a public tag. Internal deposit bounce-backs retain the canonical `keccak256(address(0) || bytes32(0))` tag.

The sender can optionally specify a `revealTo` public key (compressed secp256k1, 33 bytes) when requesting the withdrawal. If provided, the sequencer encrypts `(sender, txHash)` to that key using ECDH and populates `encryptedSender` in the withdrawal struct. The wire format is `ephemeralPubKey (33 bytes) || nonce (12 bytes) || ciphertext (52 bytes) || tag (16 bytes)` totaling 113 bytes.

Unlike user-created encrypted deposits, authenticated-withdrawal sender reveals are sequencer-created data that is hashed into the withdrawal queue. To keep zone blocks deterministic, the sequencer must not use fresh randomness when producing `encryptedSender`. It first derives a purpose-specific authenticated-withdrawal HMAC key from the registered sequencer encryption private key:

```
withdrawalHmacKey = HMAC-SHA256(uint256_be(sequencerEncryptionPrivKey), "tempo-zone-authenticated-withdrawal-derivation-key-v1")
```

Here, `uint256_be` is the 32-byte big-endian encoding of the private scalar. Using `withdrawalHmacKey`, the sequencer derives the ECIES ephemeral scalar deterministically from the zone id, `revealTo`, `sender`, `txHash`, and the 8-byte big-endian `fallbackNonce`, retrying with a counter if the derived value is not a valid secp256k1 scalar. It derives the AES-GCM nonce from the same context plus the resulting ephemeral public key. The same withdrawal is therefore byte-for-byte reproducible, while distinct withdrawals from one private transaction use different encryption material.

Two disclosure modes are available:

- **Manual reveal**: The sender shares `txHash` with a verifier off-chain. The verifier reads the public `fallbackNonce` from the withdrawal and checks `keccak256(abi.encodePacked(sender, txHash, fallbackNonce)) == senderTag`.
- **Encrypted reveal**: The holder of the `revealTo` private key decrypts `encryptedSender` to obtain `(sender, txHash)`, reads the public `fallbackNonce`, and verifies against `senderTag`. No off-chain communication needed.

During `finalizeWithdrawalBatch`, the outbox recomputes `senderTag` from the sender, `txHash`, and `fallbackNonce` stored when `requestWithdrawal` executed. The sequencer supplies only `encryptedSender`; this is trusted because a malicious sequencer could provide an incorrect ciphertext or omit it. The plaintext sender commitment remains deterministic and is covered by the same state transition checks as the rest of the withdrawal queue.

For callback withdrawals, `IWithdrawalReceiver.onWithdrawalReceived` receives the source zone ID, source portal, and `bytes32 senderTag` instead of a plaintext sender address.

### Zone-to-Zone Transfers

Closed access mode requires source queue advancement but cannot prove that the callback value itself returned. Open access mode permits direct callback-based routing without source queue advancement, whether into another zone or outside the zone system. Gateway registration remains independently enforced unless the admin also selects open gateway mode.

<br>

## Zone Execution

### Fee Accounting

Zone transactions specify which enabled TIP-20 token to use for gas fees via a `feeToken` field. The sequencer accepts all enabled tokens as gas. Transactions use Tempo transaction semantics for fee payer, max fee per gas, and gas limit.

Transaction-pool admission requires the recovered sender to hold a nonzero balance of at least one token currently enabled for the zone. This is an admission policy, not a consensus validity rule.

### Block Structure

Every non-genesis zone block begins with one inbox system transaction. Two block shapes are valid:

**Full operational block.** Transactions execute in this order:

1. `ZoneInbox.advanceTempo(header, deposits, decryptions, enabledTokens)`. Imports exactly one finalized Tempo header, authenticates and initializes the complete ordered token-enablement suffix, processes the complete ordered deposit suffix, and verifies encrypted deposit decryptions.
2. User transactions, executed in order.
3. `ZoneOutbox.finalizeWithdrawalBatch(count, blockNumber, encryptedSenders)`, when the block is the final block of a batch. It is the unique final transaction, uses the zone system caller (`msg.sender == address(0)`), and is required even for an empty withdrawal batch so the batch index advances.

**Checkpoint-only block.** The sole transaction is `ZoneInbox.advanceTempoHeaders(headers)`, which imports a nonempty consecutive range of at most 1024 finalized Tempo headers. It does not process deposits or token enablements, read Tempo state, execute user transactions, or finalize withdrawals.

A settlement batch covers one or more non-genesis zone blocks and ends with exactly one `finalizeWithdrawalBatch` call. Intermediate blocks do not finalize, and a checkpoint-only block cannot end a batch. When checkpoint-only blocks cross Tempo blocks containing portal events, their deposit and token-enablement work is deferred in exact order to the next block.

The first submitted batch begins at zone block 1 on top of the canonical genesis header. Genesis itself is not a transaction-free member of the batch. At the portal boundary, this first batch uses `prevBlockHash == 0` even though block 1's canonical parent hash is the nonzero genesis hash.

Tempo imports remain order-preserving and cannot skip ancestry. `advanceTempo` imports one immediate child of the stored checkpoint; `advanceTempoHeaders` imports a consecutive child range. A zone cannot advance beyond the finalized Tempo chain.

#### Multi-block Tempo Imports

[TIP-1096: Multi-block Tempo Imports for Zones](https://github.com/tempoxyz/tempo/blob/main/tips/tip-1096.md) decouples zone block production from Tempo block production. If a zone stops or produces more slowly than Tempo, requiring one full block for every missed Tempo block makes recovery proportional to the outage. Those blocks also require historical Tempo account and storage proofs at every intermediate root. Generating repeated historical multiproofs is computationally expensive for Reth, and some proof keys depend on decrypted deposit recipients that an independent proof service cannot discover.

An unbounded multi-header block does not solve the problem: header validation grows linearly, and all deposits and token enablements accumulated during the outage must still fit within one bounded system transaction. TIP-1096 therefore separates checkpoint advancement from operational work. During catch-up, the sequencer reserves one finalized Tempo header for the next block and groups earlier headers into bounded checkpoint-only blocks. Deposits and token enablements observed in the crossed blocks are retained in order rather than discarded. The global limits of 230 outstanding deposits and 8 outstanding token enablements ensure that the next block remains executable and provable regardless of how many empty Tempo blocks were checkpointed.

This avoids historical **state proofs** at every intermediate recovery root; it does not skip authentication. Every header remains RLP-decoded and parent-linked, the terminal block's reads remain Merkle-proven, and settlement may separately include header ancestry to an EIP-2935 anchor.

> **Note:** The prover and production Nitro verifier go live with T13. Until then, `ZonePortal` uses the existing stub verifier. Activation and transition details are specified in TIP-1096.

### Block Header Format

Zone blocks use Tempo's canonical `TempoHeader` type, field derivation, RLP encoding, and
block-hash function. A zone does not define or persist a second, simplified header type.

The block hash is `keccak256(rlp(tempo_header))`. Batch proofs commit to block hash transitions
(`prevBlockHash` to `nextBlockHash`), not raw state roots, so the proof covers the complete Tempo
header. All header fields and fork-dependent optional fields are constructed and validated
according to the Tempo rules active for that zone block.

This header rule is a clean break: implementations do not support legacy simplified zone headers
or fork-gated dual hashing, and databases containing blocks produced under older header rules must
be recreated.

### Privacy Modifications

Zone execution differs from standard Tempo execution in three areas. These changes are enforced at the EVM level, not just at the RPC layer, so they apply to all code paths including user transactions, `eth_call` simulations, and prover re-execution.

- **Account-indexed state access control.** Every getter on a zone system contract or precompile that selects privacy-bearing state by account must authorize that account against `msg.sender`. Unless a getter explicitly defines additional legitimate readers, it reverts unless `msg.sender` is the selected account. This includes AccountKeychain key configuration and limits, TIP-20 permit nonces, Nonce Manager lanes, Permit2 allowances and nonce bitmaps, FeeManager preferences and collected fees, FeeAMM liquidity balances, and ZoneInbox refund balances. The `ZoneInbox.refunds` mapping is not publicly readable; its explicit `refunds(token, owner)` getter authorizes only `owner` or the sequencer. `balanceOf(account)` authorizes only the account owner; `allowance(owner, spender)` authorizes the owner or spender. Enforcement applies to nested calls, including calls forwarded by Multicall3 or another contract, as well as direct calls.
- **Fixed gas for transfers.** All TIP-20 transfer and approve operations charge a fixed 100,000 gas regardless of storage layout. This eliminates a side channel where variable gas costs reveal whether a recipient has previously received tokens.
- **Contract creation disabled.** `CREATE` and `CREATE2` revert. The zone runs only predeploys and TIP-20 token precompiles. Arbitrary contract deployment would allow users to circumvent the execution-level privacy controls.

<br>

## Tempo State Reads

The zone reads all of its configuration from Tempo: the sequencer address, the token registry and token-enablement commitment, the deposit queue hash, and TIP-403 policy state. These reads use the finalized Tempo checkpoint.

### TempoState Predeploy

`TempoState` is deployed at `0x1c00000000000000000000000000000000000000`. It stores the finalized Tempo checkpoint that anchors the zone's Tempo L1 state view.

The durable onchain checkpoint is `tempoBlockHash` and `tempoBlockNumber`. Before the first Tempo import both are zero. Once initialized, `tempoBlockHash` is always `keccak256(RLP(TempoHeader))`, committing to the complete header contents without persisting every decoded header field.

Tempo headers are RLP-encoded as `rlp([general_gas_limit, shared_gas_limit, timestamp_millis_part, inner])`, where `inner` is a standard Ethereum header.

### Tempo Follower Mode

Zone sequencers MUST run their Tempo L1 provider in Tempo follower mode with consensus certification enabled. The follower stack syncs finalized Tempo consensus state from an upstream node and drives the execution layer from those finalized certificates.

Sequencers MUST NOT use uncertified follow mode (`--follow.nocertify`) or a generic execution-only RPC as the source for `advanceTempo` headers or Tempo state reads. Certified follower mode is required so the zone only imports Tempo headers that have reached deterministic finality; this prevents zone proofs from anchoring deposits, token configuration, sequencer rotation, or TIP-403 policy reads to state that could be reorged.

### Header Finalization

Both inbox operations use `TempoState.finalizeTempo(bytes[] headers)`. The function requires a nonempty range of at most 1024 headers. The first header must be the immediate child of the stored checkpoint; each later header must increment the block number and name the preceding header hash as its parent. The function stores the final number and hash and emits the final header's state root in `TempoBlockFinalized`.

The final imported Tempo timestamp, including its millisecond component, is a lower bound for the executing zone block timestamp. This permits catch-up blocks to use current wall-clock time without allowing a zone block to predate the Tempo state it imports.

Canonical deployed Zones start with the nonzero pre-portal Tempo checkpoint recorded in genesis. Their first import begins with its immediate child—the portal-creation block—and ordinary parent-hash and consecutive-number validation applies from that block onward. The standalone zero-hash genesis template MUST be anchored before use and MUST NOT bootstrap a deployed portal from an arbitrary later snapshot.

`advanceTempo` supplies one header to `TempoState`, while `advanceTempoHeaders` may supply a bounded consecutive range.

### L1 Storage Reads

`ZoneInbox`, `ZoneOutbox`, and TIP-403 execution read Tempo account storage from the block selected by the finalized checkpoint. Each read identifies a Tempo account and storage slot, and the zone node resolves the value through its finalized Tempo L1 provider.

The prover validates each read against the Tempo state root from the corresponding finalized header witness and includes Merkle proofs for every account and storage slot accessed by system precompiles during the batch. Since checkpoint-only blocks perform no Tempo storage reads, their intermediate roots require no state paths.

Native L1 storage reads use transaction-local cold/warm pricing keyed by Tempo account and storage slot. The first native access to a key in a transaction charges 2,100 gas and subsequent accesses charge 100 gas. This consensus access set is independent of the node's block-versioned L1 value cache, so prefetching and cache state cannot affect gas usage. Native precompile reads select the anchor by performing the ordinary local `TempoState.tempoBlockNumber` `SLOAD` before the L1 fetch.

The EVM database overlay for mirrored TIP-403 storage uses REVM's ordinary cold/warm `SLOAD` pricing and does not apply the native tariff. On the first overlay registry read, the database adapter obtains `TempoState.tempoBlockNumber` through a host-side lookup to select the L1 anchor; this is not a second EVM `SLOAD` and carries no separate gas charge. The slot remains part of the zone-state witness because its value is required for execution, while the registry slot is charged by the ordinary REVM `SLOAD`. Every L1-backed read is charged exactly once by either the native Tempo read path or the EVM overlay path.

TIP-403 policy authorization on the zone executes Tempo's registry precompile at the canonical address over raw L1 registry storage pinned to the current finalized `tempoBlockNumber`.

### Staleness and Finality

The zone's view of Tempo is the finalized Tempo block imported by its latest block. It may lag the finalized Tempo head when zone production is behind. Catch-up behavior is described in [Multi-block Tempo Imports](#multi-block-tempo-imports).

The zone node must only finalize Tempo headers that have reached finality on Tempo. Proofs should only reference finalized Tempo blocks to avoid reorg risk.

<br>

## TIP-403 Policies

Zones inherit compliance policies from Tempo automatically. Token issuers set transfer policies once on Tempo, and zones enforce them without any additional configuration.

### Policy Enforcement on Zones

The zone has a `TIP403Registry` deployed at the same address as on Tempo. This contract is read-only and does not support writing policies. Its read methods execute Tempo's registry logic over raw L1 policy storage at the finalized `TempoState.tempoBlockNumber` anchor.

Zone-side TIP-20 transfers check `isAuthorized(policyId, from)` and `isAuthorized(policyId, to)` before executing. If either check fails, the transfer reverts.

### Policy Inheritance

Issuers manage policies exclusively on Tempo. When an issuer freezes an address, updates a blacklist, or modifies a whitelist on Tempo, the zone inherits the change the next time `advanceTempo` imports a Tempo block containing the update.

If a TIP-403 policy causes a withdrawal transfer to fail, it bounces back to the sender's `zoneFallbackRecipient`.

<br>

## Redacted RPC

Zones expose a modified Ethereum JSON-RPC where every request is authenticated and every response is scoped to the caller's account. The RPC is the primary user interface and the main attack surface for privacy leaks.

### Authorization Tokens

Every RPC request must include an authorization token in the `X-Authorization-Token` HTTP header. The token proves the caller controls a Tempo account and scopes all responses to that account.

The signed message is `keccak256` of a packed encoding containing a `"TempoZoneRPC"` magic prefix, a version byte (currently `0`), the `zoneId`, `chainId`, `issuedAt`, and `expiresAt` timestamps. The wire format concatenates the signature and the 29-byte token fields, with the token fields always at the end.

A `zoneId` of `0` indicates an unscoped token valid for any zone. Zone IDs start at 1, so `0` is never a valid zone ID. The maximum validity window is 30 days (`expiresAt - issuedAt <= 2592000`). A clock skew tolerance of 60 seconds is allowed for `issuedAt`.

The RPC server rejects authorization tokens where:

- `zoneId` does not match the zone's configured `zoneId` and is not `0`.
- `chainId` does not match the zone's chain ID.
- `expiresAt - issuedAt > 2592000`.
- `expiresAt <= now`.
- `issuedAt > now + 60`.
- The signature is malformed or does not verify.
- For Keychain signatures: the signing key is not authorized, revoked, or expired in the zone's `AccountKeychain`.

Requests without an authorization token receive HTTP `401`. Requests with an invalid or expired token receive HTTP `403`.

### Signature Types

Authorization token signatures follow the same format as Tempo transaction signatures:

| Type | Detection | Authentication |
|------|-----------|----------------|
| secp256k1 | 65 bytes, no prefix | Standard `ecrecover` |
| P256 | Prefix `0x01`, 130 bytes | Public key embedded in signature |
| WebAuthn | Prefix `0x02`, variable length | P256 key via WebAuthn assertion |
| Keychain V1 | Prefix `0x03` | Wraps inner sig + `user_address`, authenticates as root account |
| Keychain V2 | Prefix `0x04` | Same as V1 but binds `user_address` into signing hash |

Keychain keys allow session keys and scoped access keys to authenticate to the RPC with the same permissions as the root account. The zone has its own independent `AccountKeychain` instance, not mirrored from Tempo. Users must register keychain keys on the zone directly.

### Method Access Control

The RPC uses a default-deny model. Any method not explicitly listed returns `-32601` (method not found). Exposed methods fall into two categories:

**Allowed.** `eth_chainId`, `eth_blockNumber`, `eth_gasPrice`, `eth_maxPriorityFeePerGas`, `eth_feeHistory`, `eth_getBlockByNumber` and `eth_getBlockByHash` (without full transactions), `eth_syncing`, `eth_coinbase`, `net_version`, `net_listening`, `web3_clientVersion`, `web3_sha3`, `zone_getAuthorizationTokenInfo`, `zone_getZoneInfo`, and `zone_getEncryptionKey`.

Fee quotes are caller-independent: `eth_gasPrice` returns the fixed T1 gas price and `eth_maxPriorityFeePerGas` returns `0`.

**Scoped.** Available to any authenticated caller but filtered to the caller's account:

- `eth_getBalance`, `eth_getTransactionCount`: return `0x0` for non-self queries (no error, to avoid leaking account existence).
- `eth_getTransactionByHash`, `eth_getTransactionReceipt`: return `null` if the caller is not the sender.
- `eth_sendRawTransaction`, `eth_sendRawTransactionSync`: reject if the transaction sender does not match the authenticated account.
- `eth_fillTransaction`: fills but does not sign an unsigned transaction, with the same authenticated `from` enforcement as simulation methods.
- `eth_call`, `eth_estimateGas`: `from` must equal the authenticated account. Account-indexed reads are then protected by the execution-level access controls described in [Privacy Modifications](#privacy-modifications), including for nested calls. State override sets and block override objects are rejected.
- `eth_getLogs`, `eth_getFilterLogs`, `eth_getFilterChanges`: filtered to TIP-20 events where the caller is a relevant party (see [Event Filtering](#event-filtering)).
- `eth_newFilter`, `eth_newBlockFilter`, `eth_uninstallFilter`: allowed, filters are scoped to the authenticated account.

Methods outside this allowlist are not classified separately as restricted or disabled. Raw state and full block endpoints, mining and mempool methods, and all `debug_*`, `admin_*`, and `txpool_*` methods return `-32601`. Sequencers and operators use the unrestricted RPC on port 8545 instead of receiving elevated access through an authorization token. Requests for full transactions through the otherwise-allowed `eth_getBlockByNumber` and `eth_getBlockByHash` methods return `-32005` and must likewise use the unrestricted endpoint.

**Note on timing side channel attacks:** Scoped methods returning empty values could technically be timed to estimate if the values exist. However, (1) Benchmarked timing differences are very small and (2) The values like `transactionHash` etc... can't be correlated to actual user data, so any leaked signal is not material.

### Block Responses

Block responses from the redacted RPC are modified:

- The `transactions` field is always an empty array, regardless of the `include_transactions` parameter.
- Header fields that reveal aggregate execution activity are zeroed or emptied: `gasUsed`, `transactionsRoot`, `receiptsRoot`, `stateRoot`, `extraData`, `logsBloom`, `size`, optional blob gas fields (`blobGasUsed`, `excessBlobGas`), and optional withdrawal fields (`withdrawals`, `withdrawalsRoot`). The Bloom filter summarizes all log topics and emitting addresses in the block, and the other redacted fields reveal transaction count, payload size, state changes, receipt/log activity, blob usage, or withdrawal activity.
- Public block identity and timing fields such as `number`, `hash`, `parentHash`, `timestamp`, and fee metadata remain visible.

Sequencers and operators retrieve full block data from the unrestricted RPC on port 8545.

### Fee History

`eth_feeHistory` uses the underlying node implementation for block range resolution, history limits, and reward percentile validation, then redacts activity-derived fields before returning the response:

- `baseFeePerGas` is set to the public zone T0 base fee for every returned entry.
- `gasUsedRatio`, `baseFeePerBlobGas` and `blobGasUsedRatio` are set to `0`.
- `reward`, when requested, is returned with the same shape but every value set to `0`.

### Event Filtering

All log queries are restricted to TIP-20 events where the authenticated account is a relevant party:

| Event | Relevant if |
|-------|-------------|
| `Transfer(from, to, amount)` | `from == caller` OR `to == caller` |
| `Approval(owner, spender, amount)` | `owner == caller` OR `spender == caller` |
| `TransferWithMemo(from, to, amount, memo)` | `from == caller` OR `to == caller` |
| `Mint(to, amount)` | `to == caller` |
| `Burn(from, amount)` | `from == caller` |

All other events (system events, configuration events) are filtered out. The `address` filter parameter must be a zone token address or omitted. The RPC server injects topic filters to restrict indexed address parameters to the caller, then post-filters results as a final pass.

To avoid leaking how much activity occurred in a block, some fields of returned logs are redacted:

- `transactionIndex` is set to `0` on every log, so the caller cannot infer its transaction's position among, or the number of, other transactions in the block.
- `logIndex` is renumbered per transaction rather than exposing the log's global position in the block. `(transactionHash, logIndex)` is stable and consistent for a given log across `eth_getLogs`, `eth_getFilterLogs`, `eth_getFilterChanges`, `eth_getTransactionReceipt`, and `eth_subscribe("logs")`.


### WebSocket Subscriptions

WebSocket connections follow the same authorization model. The authorization token is provided during the handshake and scopes all subscriptions for that connection.

- `eth_subscribe("newHeads")`: allowed, pushes block headers with the same header redaction as HTTP block responses.
- `eth_subscribe("logs")`: scoped to the authenticated account using the same event filtering rules.
- `eth_subscribe("newPendingTransactions")`: disabled.

The connection is terminated when the authorization token expires. For keychain-authenticated connections, the server must also terminate the connection within 1 second of importing a block that revokes the keychain key.

### Zone-Specific Methods

The authentication-independent Zone metadata methods are available on both the
operator RPC transports and the authenticated redacted RPC.

| Method | Access | Description |
|--------|--------|-------------|
| `zone_getAuthorizationTokenInfo` | Authenticated redacted RPC only | Returns the authenticated account address and token expiry |
| `zone_getZoneInfo` | Operator RPC and authenticated redacted RPC | Returns `zoneId`, `isAccessEnforced`, `isGatewayOpen`, `zoneTokens`, `sequencers`, `chainId`, and `tempoBlockNumber` |
| `zone_getEncryptionKey` | Operator RPC and authenticated redacted RPC | Returns the active sequencer encryption key at the current Tempo L1 head |

`zone_getEncryptionKey` reads the active key directly from the portal at the current Tempo L1 head.
Its response is:

```ts
{
  x: Hex,
  yParity: 2 | 3,
  keyIndex: bigint,
}
```

This is the portal's `encryptionKeyAtBlock` return value without additional wrapping. The key index
uses JSON-RPC quantity encoding. Key rotation is visible immediately on L1 and does not wait for the
Zone to process the corresponding Tempo block.

There are no state-changing methods via authorization token. Withdrawals require a signed transaction submitted via `eth_sendRawTransaction`.

### Error Codes

| Code | Message | When |
|------|---------|------|
| `-32001` | Authorization token required | No token provided |
| `-32002` | Authorization token expired | Token has expired |
| `-32003` | Transaction rejected | Sender mismatch on `eth_sendRawTransaction` |
| `-32004` | Account mismatch | `from` mismatch on `eth_call` / `eth_estimateGas` |
| `-32005` | Sequencer only | Full block transactions require the unrestricted operator RPC |
| `-32006` | Method disabled | WebSocket subscription kind is not available on zones |
| `-32601` | Method not found | Method is not exposed by the redacted RPC allowlist |

Methods where the user explicitly supplies a mismatched parameter return explicit errors (the user already knows the address they provided). Methods that query about other accounts return silent dummy values (`0x0`, `null`, empty results) to avoid revealing "data exists but you can't see it."

<br>

## Proving System

The proving system is proof-agnostic. The core is a state transition function that takes trusted configuration and a witness, executes zone blocks, and outputs commitments for onchain verification. The onchain verifier is abstracted behind `IVerifier`, and the portal does not care how the proof was produced. The Nitro proving backend runs the state transition function in an AWS Nitro Enclave and binds its output into a signed Nitro attestation.

The prover assumes [multi-block Tempo imports](#multi-block-tempo-imports) are active. It authenticates the complete Tempo header sequence while requiring Tempo state proofs only for checkpoints where execution actually reads Tempo state.

### State Transition Function

The entry point is:

```rust
pub fn prove_zone_batch(
    config: &SpfConfig,
    witness: BatchWitness,
) -> Result<BatchOutput, Error>
```

It takes trusted verifier configuration and a complete witness of zone blocks and their dependencies, executes EVM state transitions (including system transactions), and outputs commitments for onchain verification. `SpfConfig` contains the composed `ZoneChainSpec`; `BatchWitness` is untrusted. The function derives the zone chain ID from the witness's parent chain ID and zone ID and requires the derived chain to match the trusted configuration. The execution portal is derived from the zone ID encoded in the trusted chain specification using the TIP-1091 portal address rule: the 12-byte prefix `0x5ad000000000000000000000` followed by the zone ID encoded as an 8-byte big-endian integer.

The core commitment is the zone block hash transition, not the raw state root.

### Witness Structure

The witness contains everything needed to re-execute one batch:

- **PublicInputs**: `parent_chain_id`, `zone_id`, `tempo_block_number`, `anchor_block_number`, `anchor_block_hash`, and `expected_withdrawal_batch_index`.
- **BatchWitness**: the public inputs, the canonical parent `TempoHeader`, zone blocks in execution order, the initial zone-state witness, the Tempo-state witness, and optional Tempo ancestry headers used to reach the settlement anchor.
- **TempoImport**: either a `Full` import containing one header and its portal-work calldata, or a `CheckpointOnly` import containing a bounded consecutive header range.
- **ZoneBlock**: block metadata, the Tempo import, optional finalization inputs, and raw signed user transaction envelopes.
- **ZoneStateWitness**: a deduplicated pool of zone-state trie nodes and a bytecode pool. The parent header supplies the initial state root. EIP-2935 history-contract slots used by `BLOCKHASH` are ordinary witnessed state.
- **TempoStateWitness**: the RLP-encoded Tempo header already bound in the parent zone state and a deduplicated pool of Tempo-state trie nodes spanning every root read during the batch.

Missing witness data is an error. A prover cannot cause an unavailable nonzero value or bytecode preimage to be interpreted as empty.

### Input Schematic

The prover inputs are nested containers. `BatchWitness` is the top-level object passed into `prove_zone_batch`, and the schematic below shows one representative entry for repeated collections such as `ZoneBlock[i]` and `QueuedDeposit[j]`. To keep the picture readable, the boxes list field names rather than repeating every Rust scalar type.

```mermaid
flowchart TB
    subgraph BW["BatchWitness"]
        direction TB

        PI["PublicInputs<br/>parent_chain_id<br/>zone_id<br/>tempo_block_number<br/>anchor_block_number<br/>anchor_block_hash<br/>expected_withdrawal_batch_index"]
        PH["parent_header: TempoHeader<br/>state_root<br/>number<br/>timestamp<br/>canonical header fields"]

        subgraph ZBL["zone_blocks"]
            direction TB
            ZB["ZoneBlock[i]<br/>number<br/>parent_hash<br/>timestamp<br/>timestamp_millis_part<br/>beneficiary<br/>tempo_import<br/>finalize_withdrawal_batch_count<br/>finalize_withdrawal_batch_encrypted_senders<br/>transactions"]

            subgraph TI["TempoImport"]
                direction LR
                FULL["Full<br/>header_rlp<br/>deposits<br/>decryptions<br/>enabled_tokens"]
                CHECKPOINT["CheckpointOnly<br/>headers_rlp"]
            end

            subgraph DEP["Full.deposits"]
                direction TB
                QD["QueuedDeposit[j]<br/>depositType<br/>depositData<br/>rejected"]
                DD["DecryptionData[k]<br/>sharedSecret<br/>sharedSecretYParity<br/>cpProof"]
                QD ~~~ DD
            end

            ZB ~~~ FULL
            FULL ~~~ QD
            FULL ~~~ CHECKPOINT
        end

        ZSW["ZoneStateWitness<br/>node_pool<br/>bytecodes"]
        TSW["TempoStateWitness<br/>initial_tempo_header_rlp<br/>node_pool"]
        AH["tempo_ancestry_headers<br/>header bytes [0..n]"]

        PI ~~~ PH
        PH ~~~ ZB
        ZB ~~~ ZSW
        ZSW ~~~ TSW
        TSW ~~~ AH
    end
```

### Detailed Input Definitions

The prover-side inputs are defined concretely below. Types that mirror the onchain ABI (`QueuedDeposit`, `DecryptionData`, `EnabledToken`, and the transition structs) keep the same field ordering and semantics as the interface definitions in [Common Types](#common-types). `Bytes` contains exact wire bytes. The `QueuedDeposit.rejected` ABI field does not authorize a sequencer decision: every user deposit still consumes one `DecryptionData` entry and follows onchain verification.

```rust
/// Trusted network configuration for zone execution.
/// Selected by the verifier rather than supplied by the witness.
pub struct SpfConfig {
    chain_spec: Arc<ZoneChainSpec>,
}

/// Public values that the verifier binds to a submitted batch proof.
pub struct PublicInputs {
    /// Parent Tempo chain ID used to derive the zone EVM chain ID.
    pub parent_chain_id: u64,

    /// Zone identifier used with parent_chain_id to derive the zone chain ID.
    pub zone_id: u32,

    /// Final Tempo checkpoint committed by this batch.
    pub tempo_block_number: u64,

    /// Tempo block whose hash anchors the proof.
    pub anchor_block_number: u64,

    /// Canonical hash of anchor_block_number.
    pub anchor_block_hash: B256,

    /// ZoneOutbox withdrawal batch index expected by the portal.
    pub expected_withdrawal_batch_index: u64,
}

/// Complete prover input for one zone batch.
pub struct BatchWitness {
    /// Values committed by the verifier.
    pub public_inputs: PublicInputs,

    /// Canonical header of the first zone block's parent.
    pub parent_header: TempoHeader,

    /// Zone blocks in execution order.
    pub zone_blocks: Vec<ZoneBlock>,

    /// Zone state reachable from parent_header.state_root.
    pub zone_state_witness: ZoneStateWitness,

    /// Tempo state nodes for all roots read during execution.
    pub tempo_state_witness: TempoStateWitness,

    /// Headers from tempo_block_number + 1 through anchor_block_number.
    /// Empty in direct-anchor mode.
    pub tempo_ancestry_headers: Vec<Bytes>,
}

/// Typed inputs for the opening ZoneInbox system transaction.
pub enum TempoImport {
    /// Import one Tempo header and process its complete portal-work suffix.
    Full {
        /// The one Tempo header imported by ZoneInbox.advanceTempo.
        header_rlp: Bytes,
        deposits: Vec<QueuedDeposit>,
        decryptions: Vec<DecryptionData>,
        enabled_tokens: Vec<EnabledToken>,
    },

    /// Authenticate Tempo ancestry without processing portal work.
    CheckpointOnly {
        /// Headers imported by ZoneInbox.advanceTempoHeaders.
        headers_rlp: Vec<Bytes>,
    },
}

/// Zone block input, including its system-call inputs and raw user transactions.
pub struct ZoneBlock {
    /// Block number.
    pub number: u64,

    /// Parent block hash.
    pub parent_hash: B256,

    /// Timestamp in seconds.
    pub timestamp: u64,

    /// Millisecond component of the timestamp.
    pub timestamp_millis_part: u64,

    /// Fee recipient committed by the block header.
    pub beneficiary: Address,

    /// Inputs for the opening ZoneInbox system transaction.
    pub tempo_import: TempoImport,

    /// Count passed to finalization; present only in the final block.
    pub finalize_withdrawal_batch_count: Option<U256>,

    /// Exact encryptedSenders calldata. Its length must equal count.
    pub finalize_withdrawal_batch_encrypted_senders: Vec<Bytes>,

    /// Raw signed Tempo EIP-2718 transaction envelopes in execution order.
    pub transactions: Vec<Bytes>,
}

/// Stateless zone state input.
pub struct ZoneStateWitness {
    /// Deduplicated raw RLP-encoded zone MPT nodes.
    pub node_pool: Vec<Bytes>,

    /// Deduplicated bytecode preimages indexed by keccak256(bytecode).
    pub bytecodes: Vec<Bytes>,
}

/// Stateless Tempo state input.
pub struct TempoStateWitness {
    /// Header for the Tempo checkpoint stored in the parent zone state.
    pub initial_tempo_header_rlp: Bytes,

    /// Deduplicated raw RLP-encoded Tempo MPT nodes.
    pub node_pool: Vec<Bytes>,
}

/// Commitments returned by a successful zone batch transition.
pub struct BatchOutput {
    /// Number of the final executed Zone header.
    pub next_zone_height: u64,

    /// Hash transition covering every zone block in the batch.
    pub block_transition: BlockTransition,

    /// Progress of the ZoneInbox deposit queue during the batch.
    pub deposit_queue_transition: DepositQueueTransition,

    /// Progress of the append-only portal token-enablement prefix.
    pub token_enablement_transition: TokenEnablementTransition,

    /// Hash chain created by finalizing the batch's withdrawals.
    pub withdrawal_queue_hash: B256,

    /// Batch index committed by ZoneOutbox.lastBatch.
    pub last_batch_commitment: LastBatchCommitment,
}

/// The portion of ZoneOutbox.lastBatch independently committed by the SPF.
pub struct LastBatchCommitment {
    /// Withdrawal batch index read from the post-state.
    pub withdrawal_batch_index: u64,
}
```

### Shared Trie Proof Format

`ZoneStateWitness` and `TempoStateWitness` both use the same trie-proof encoding:

- `node_pool` is a deduplicated list of raw RLP-encoded nodes. The prover computes `keccak256(rlp(node))` for each entry and builds its own hash-to-node index for proof traversal.
- Execution derives every account and storage key from the state operation being performed. Verification walks the account trie using `keccak256(account)` and, when needed, the storage trie using `keccak256(slot)`, fetching branch, extension, and leaf nodes from the prover's hash-to-node index constructed from `node_pool`. The account and storage values are decoded from those leaves.
- An account leaf commits to its `code_hash`, but not the bytecode preimage. For a non-empty code hash, the prover must find a matching entry in `ZoneStateWitness.bytecodes` and require `keccak256(bytecode) == code_hash` before executing that code.
- Missing leaves are represented by valid non-membership proofs. An absent account is interpreted as the canonical empty account: `nonce = 0`, `balance = 0`, `code = None`, `code_hash = KECCAK_EMPTY`, and an empty storage trie. An absent storage leaf is interpreted as zero.
- Client databases may still retain historical trie nodes that are no longer reachable from the current root, but those stale nodes are irrelevant to proof verification because only nodes reachable from the bound root contribute to the proof.

`ZoneStateWitness` applies this shared trie proof format to `parent_header.state_root` at batch start. To initialize execution, the prover indexes `node_pool` and creates a witness-backed state reader anchored at that root. On each first access, it derives the requested account or storage key from execution, verifies and decodes the matching trie leaf, and materializes the result into the in-memory execution state. Missing trie nodes or bytecode preimages are errors; they must not silently default to zero or empty code.

`TempoStateWitness` initializes the active Tempo root from `initial_tempo_header_rlp`. Before any Tempo read, the prover decodes that header, requires its hash and block number to equal `TempoState.tempoBlockHash` and `TempoState.tempoBlockNumber` in the initial zone state, and uses its decoded `state_root`. The shared node pool may contain paths for multiple `Full` import roots in the batch.

### Batch Output

The state transition function produces:

| Field | Description |
|-------|-------------|
| `block_transition` | `prev_block_hash` to `next_block_hash` covering all blocks in the batch |
| `deposit_queue_transition` | Deposit queue progress from the previous `(processed_hash, deposit_number)` pair to the next `(processed_hash, deposit_number)` pair |
| `token_enablement_transition` | Enabled-token progress from the previous processed count to the next processed count |
| `withdrawal_queue_hash` | Hash chain of withdrawals finalized in this batch (`0` if none) |
| `last_batch_commitment` | `withdrawal_batch_index` read from `ZoneOutbox.lastBatch` |

The first submitted batch is represented specially at the portal boundary. Its witness begins with zone block 1 and uses the canonical genesis header as `parent_header`; `block_transition.prevBlockHash` is the portal's zero pre-genesis sentinel rather than the nonzero canonical genesis hash. Later batches use the actual parent header hash.

### Block Execution (Stateless prover execution function)

The stateless execution function must reject the witness on any failed check, missing read, or inconsistent state transition. A correct implementation proceeds in the following order:

1. **Bind trusted zone configuration.**
   Reject an empty batch. Derive the zone chain ID from `public_inputs.parent_chain_id` and `public_inputs.zone_id` under the rules in [Chain ID](#chain-id), require it to match `config.chain_spec`, and derive the canonical TIP-1091 portal from the zone ID in `config.chain_spec`. All portal reads during execution MUST use this derived address.

2. **Initialize the zone state.**
   Apply the [shared trie proof format](#shared-trie-proof-format) to `parent_header.state_root` and `zone_state_witness`. Index the node pool, resolve account and storage values on first access, and require every non-empty code hash to have a matching bytecode preimage. `BLOCKHASH(n)` resolves through the EIP-2935 history contract at slot `n % 8191`; missing trie nodes or bytecode are errors rather than zero values. Capture the pre-state `ZoneInbox.processedDepositQueueHash`, `processedDepositNumber`, and `processedEnabledTokenCount`; these become the previous ends of the public queue transitions.

3. **Initialize the Tempo state.**
   Decode `tempo_state_witness.initial_tempo_header_rlp`, index its state root over the Tempo node pool, and require its number and hash to equal `TempoState.tempoBlockNumber` and `TempoState.tempoBlockHash` read from the parent zone state. See [Tempo State Witness](#tempo-state-witness).

4. **Validate each zone block's chain and batch shape.**
   Require `parent_hash` to equal the preceding canonical header hash, `number` to increment by one, and the timestamp not to regress. Every block must contain a nonempty `TempoImport`. A checkpoint-only block must be intermediate and contain no user transactions or withdrawal-finalization inputs. Other intermediate blocks must not finalize withdrawals. The final block must contain finalization. Whenever finalization is present, `encrypted_senders.len() == count`; without a count the array must be empty. These shapes mirror [Block Structure](#block-structure).

   `beneficiary` supplies the block environment and is committed by the resulting header. Production authority is checked by the node's leadership schedule and follower validation, while settlement authorization is provided by the quorum certificate; it is not a separate `PublicInputs.sequencer` check in the state transition function.

5. **Select and authenticate the block's Tempo import.**
   Decode every imported header without trailing bytes. The first header must extend the stored Tempo checkpoint and every additional checkpoint-only header must extend its predecessor by both parent hash and block number. A checkpoint-only range contains at most 1024 headers; a `Full` import contains exactly one. The zone block timestamp, including its millisecond component, must be at or after the final imported Tempo timestamp. Use the final header's state root as the active Tempo witness root for this block. See [Multi-block Tempo Imports](#multi-block-tempo-imports) and [Header Finalization](#header-finalization).

6. **Execute the opening system transaction.**
   For `CheckpointOnly`, execute `ZoneInbox.advanceTempoHeaders(headers)`. It advances only the authenticated checkpoint and is the block's sole transaction.

   For `Full`, execute `ZoneInbox.advanceTempo(header, deposits, decryptions, enabledTokens)`. Require at most `MAX_UNPROCESSED_DEPOSITS` (230) deposits and `MAX_UNPROCESSED_TOKEN_ENABLEMENTS` (8) token enablements. Against the imported Tempo root, authenticate the exact ordered enabled-token suffix from `processedTokenEnablementHash` to the portal's `tokenEnablementHash`, initialize those tokens, and update the processed hash and count as specified in [Token Enablement Commitment](#token-enablement-commitment).

   Process deposits oldest-first under the [Deposit Queue](#deposit-queue) rules. Every encrypted user deposit consumes exactly one `DecryptionData` entry in deposit order; missing or extra entries make the system transaction revert. Verify the Chaum-Pedersen proof and AES-GCM ciphertext as described in [Onchain Decryption Verification](#onchain-decryption-verification). Invalid encryption or a failed recipient mint enqueues a bounce-back, while malformed queue inputs or inconsistent queue commitments reject the witness. Token initialization precedes deposit processing. In either import form, the opening transaction must leave `TempoState.tempoBlockHash` equal to `keccak256` of the final imported header. All system calldata, logs, receipts, and state changes contribute to the resulting block hash.

7. **Execute user transactions.**
   Decode each supplied byte string as one complete signed Tempo EIP-2718 envelope, reject system transactions in the user list, recover its signer, and execute the transactions in order under the current zone EVM environment.

8. **Finalize withdrawals in the terminal block.**
   After all terminal-block user transactions, execute `ZoneOutbox.finalizeWithdrawalBatch(count, block.number, encryptedSenders)` as the final system transaction from `address(0)`. It updates `ZoneOutbox.lastBatch` and constructs the public withdrawal hash chain. The encrypted-sender array is part of each encoded withdrawal and follows [Authenticated Withdrawals](#authenticated-withdrawals). No intermediate or checkpoint-only block may call finalization; see [Withdrawal Batching](#withdrawal-batching).

9. **Assemble and carry the canonical block header.**
   Apply production pre- and post-execution changes under the rules selected by the zone block timestamp, calculate the witness-backed post-state root, and use Tempo's canonical block assembler to derive the transaction root, receipt root, logs bloom, gas fields, timestamp fields, and fork-dependent fields specified in [Block Header Format](#block-header-format). Compute the block hash from the complete header and carry that header into the next block.

10. **Extract post-state commitments.**
    Read the final `ZoneInbox.processedDepositQueueHash`, `ZoneInbox.processedDepositNumber`, `ZoneInbox.processedEnabledTokenCount`, `ZoneOutbox.lastBatch.withdrawalQueueHash`, `ZoneOutbox.lastBatch.withdrawalBatchIndex`, `TempoState.tempoBlockNumber`, and `TempoState.tempoBlockHash`. Require the withdrawal batch index to equal `public_inputs.expected_withdrawal_batch_index`.

11. **Validate the final Tempo checkpoint and settlement anchor.**
    Require the final `TempoState.tempoBlockNumber` to equal `public_inputs.tempo_block_number`. In direct mode, require `anchor_block_number == tempo_block_number`, no ancestry headers, and exact hash equality. In ancestry mode, require exactly `anchor_block_number - tempo_block_number` headers, validate their complete RLP, consecutive numbers, and parent hashes, and require the chain to end at `anchor_block_hash`. See [Anchor Block Validation](#anchor-block-validation).

12. **Return the public output.**
    Construct the [Batch Output](#batch-output) from the captured pre-state and final post-state. Set `next_zone_height` to the final assembled header number and the next block hash to its hash; set the next deposit hash and number and next enabled-token count to the final inbox values; and set the withdrawal queue hash and batch index from `ZoneOutbox.lastBatch`. For a batch beginning at block 1, substitute the zero portal sentinel for the block transition's previous hash.

### Tempo State Witness

System contracts read Tempo state during execution (deposit queue hash, token-enablement commitment, token registry, encryption keys, fee and pause configuration, and TIP-403 policies). `TempoStateWitness` applies the [shared trie proof format](#shared-trie-proof-format) to the Tempo root bound by `TempoState` at the moment of each read. Its `initial_tempo_header_rlp` supplies the initial active root. Later blocks use the root decoded from the header passed to `advanceTempo`.

The witness includes:

- The RLP-encoded header for the initially bound Tempo checkpoint. Its hash and block number must match the `TempoState` values in the initial zone state.
- A deduplicated `node_pool` of raw RLP-encoded MPT nodes covering every Tempo root read during the batch.

Reads are derived, verified, and decoded on demand during execution: the `TempoState.readTempoStorageSlot` invocation supplies the account and storage slot, and the active Tempo header supplies the bound root. `ZoneStateWitness` is rooted once at `parent_header.state_root`, while `TempoStateWitness` reads are verified against the active Tempo checkpoint. Checkpoint-only blocks perform no Tempo state reads, so their intermediate roots require no state paths.

`tempo_ancestry_headers` are separate from the state witness: they contain headers rather than state proofs and authenticate the final checkpoint to a newer EIP-2935 settlement anchor.

### Nitro Attestation

The Nitro settlement profile uses AWS Nitro Enclaves. After successful replay, the prover computes the EIP-712 struct hash of the following value:

```solidity
/// Data placed in the Nitro attestation document's `user_data` field.
struct NitroBatchAttestation {
    uint256 parentChainId;
    address verifier;
    uint32 zoneId;
    uint64 tempoBlockNumber;
    uint64 anchorBlockNumber;
    bytes32 anchorBlockHash;
    uint64 expectedWithdrawalBatchIndex;
    uint256 nextZoneHeight;
    bytes32 prevBlockHash;
    bytes32 nextBlockHash;
    bytes32 prevProcessedHash;
    bytes32 nextProcessedHash;
    uint64 prevDepositNumber;
    uint64 nextDepositNumber;
    uint64 prevProcessedTokenCount;
    uint64 nextProcessedTokenCount;
    bytes32 withdrawalQueueHash;
    bytes32 verifierConfigHash;
}
```

`verifier` is the fixed `ZONE_VERIFIER_ADDRESS`, and `verifierConfigHash` is `keccak256(0x01)`. The remaining fields come from `PublicInputs` and `BatchOutput`. Binding the parent chain, verifier, and zone prevents cross-domain reuse because the portal is uniquely derived from the zone ID on that parent chain; binding the executed Zone height, both ends of every transition, the withdrawal index and hash, and the exact anchor prevents reuse for another batch.

When checking the attestation, the Nitro verifier MUST reconstruct `parentChainId` from `block.chainid`, `verifier` from `address(this)`, and MUST require `msg.sender == portalAddress(zoneId)` using the same canonical TIP-1091 derivation as the SPF. Merely checking `zoneId == IZonePortal(msg.sender).zoneId()` is insufficient because an arbitrary contract can report that ID. It reconstructs the remaining digest fields from the arguments supplied by `ZonePortal` to `verify`; it MUST NOT trust domain values copied from the proof or prover witness.

The prover asks the Nitro Secure Module to place this 32-byte hash in the attestation document's `user_data`. It returns:

```rust
/// Proof material returned by an attesting prover.
pub struct ProofBundle {
    pub verifier_config: Bytes, // exactly 0x01
    pub proof: Bytes,           // raw COSE/CBOR Nitro attestation document
}
```

The Nitro verifier MUST validate the COSE signature and certificate chain, enforce the accepted enclave image/PCR policy, require `user_data` to equal the canonical batch hash, and reject any verifier configuration other than the policy it implements. The portal itself treats `verifierConfig` and `proof` as opaque bytes.

### Prover Service and Deployment

The settlement prover runs the state transition function inside a Nitro Enclave. The parent node collects the complete `BatchWitness`; the enclave performs no RPC or filesystem reads while handling it. A configured settlement sequencer MUST use a remote attesting prover. In-process execution is available for observational shadow validation but does not produce a settlement proof.

The service accepts one request and returns one response per connection. Each frame is a four-byte big-endian payload length followed by CBOR and is bounded by a configurable limit of 2 GiB by default. The request contains `version`, a caller-selected `requestId`, and `witness`; byte-heavy witness fields use CBOR byte strings rather than human-readable hex. Decoding is schema-driven and rejects unknown, duplicate, or trailing request data. A successful response echoes the version and request ID and contains both `BatchOutput` and `ProofBundle`. The prover accepts only chain specifications configured by its operator; a witness cannot supply its own trusted chain schedule. A production deployment MUST select the canonical per-zone chain specification independently of the witness and derive the portal from its zone ID.

Errors use stable machine-readable categories: `malformed_request`, `unsupported_version`, `unsupported_chain`, `verification_failed`, `attestation_unavailable`, `request_too_large`, `truncated_frame`, and `internal_error`. A successful state transition for which the Nitro Secure Module cannot produce an attestation returns `attestation_unavailable`, not an unattested success.

<br>

## Batch Submission

Any active sequencer may submit a batch to Tempo via `ZonePortal.submitBatch()`. Each batch covers one or more zone blocks, includes a proof that the state transition was executed correctly, and carries a threshold certificate from the active sequencer set.

### submitBatch

The call takes the following parameters:

| Parameter | Description |
|-----------|-------------|
| `tempoBlockNumber` | The Tempo block the zone committed to via `TempoState` |
| `recentTempoBlockNumber` | A recent Tempo block for ancestry validation (`0` for direct lookup) |
| `blockTransition` | Zone block hash transition: `prevBlockHash` to `nextBlockHash` |
| `depositQueueTransition` | Deposit queue progress from the previous `(processedHash, depositNumber)` pair to the next `(processedHash, depositNumber)` pair |
| `tokenEnablementTransition` | Enabled-token progress from the previous processed count to the next processed count |
| `withdrawalQueueHash` | Hash chain of withdrawals finalized in this batch (`0` if none) |
| `verifierConfig` | Opaque payload for the verifier (domain separation, attestation data) |
| `proof` | The proof or attestation produced by the proving backend |
| `zoneHeight` | Strictly increasing final executed Zone height committed by the proof and certificate |
| `signatures` | Distinct active-sequencer signatures meeting `sequencerThreshold` |

The EIP-712 settlement commitment binds the Tempo chain, portal, zone ID, sequencer-set version,
zone height, withdrawal batch index, verifier, Tempo anchor, block transition, deposit transition,
token-enablement transition, withdrawal queue hash, and verifier configuration. Duplicate,
malformed, unregistered, or stale-version signatures are rejected. The transaction submitter has no
distinguished authority beyond being an active sequencer.

The settlement monitor resolves one immutable anchor before proving and uses it for the prover public inputs, follower quorum proposal, and submitted calldata. It may reuse that anchor across retries while it remains canonical and EIP-2935-accessible. If the anchor expires or becomes noncanonical, proving and certification are rebuilt together.

The portal additionally requires `blockTransition.prevBlockHash` to equal its current `blockHash`. Deposit and enabled-token counts must be continuous with the portal's accepted cursors, monotonic, and no greater than their respective queue lengths.

On success, the portal:

1. Updates `blockHash` to `nextBlockHash`.
2. Updates `lastSyncedTempoBlockNumber` to `tempoBlockNumber`, `lastProcessedDepositNumber` to `depositQueueTransition.nextDepositNumber`, and `lastProcessedEnabledTokenCount` to `tokenEnablementTransition.nextProcessedTokenCount`.
3. Advances `withdrawalBatchIndex`.
4. Updates `zoneHeight`.
5. If `withdrawalQueueHash` is non-zero, assigns the current logical withdrawal queue `tail`, writes the hash chain to `slots[tail]`, and advances `tail`.
6. Emits `BatchSubmitted` with the accepted processed counts and assigned logical `withdrawalQueueIndex`, or `NO_QUEUE_INDEX` for an empty batch.

### Verifier Interface

The portal calls the verifier to validate each batch:

```solidity
interface IVerifier {
    function verify(
        uint32 zoneId,
        uint64 tempoBlockNumber,
        uint64 anchorBlockNumber,
        bytes32 anchorBlockHash,
        uint64 expectedWithdrawalBatchIndex,
        uint256 nextZoneHeight,
        BlockTransition calldata blockTransition,
        DepositQueueTransition calldata depositQueueTransition,
        TokenEnablementTransition calldata tokenEnablementTransition,
        bytes32 withdrawalQueueHash,
        bytes calldata verifierConfig,
        bytes calldata proof
    ) external view returns (bool);
}
```

The portal passes its `zoneId`, computes `anchorBlockNumber` and `anchorBlockHash` from the submission parameters (see [Anchor Block Validation](#anchor-block-validation)), and passes them alongside the portal's current `withdrawalBatchIndex + 1` as `expectedWithdrawalBatchIndex`. It also forwards the exact `uint256 nextZoneHeight` supplied to `submitBatch`, without narrowing it; verification MUST bind this value to the final executed Zone header number before the portal stores it. The `verifierConfig` and `proof` are opaque to the portal. Sequencer authorization is enforced separately by the portal's versioned threshold certificate.

### Anchor Block Validation

The portal needs to verify that the zone's view of Tempo (via `TempoState`) is anchored to a real Tempo block. It looks up a block hash via the EIP-2935 block hash history precompile and passes it to the verifier.

If `recentTempoBlockNumber` is `0`, the portal looks up `tempoBlockNumber` directly from EIP-2935. The proof must show that the zone's `tempoBlockHash` matches this hash.

If `recentTempoBlockNumber` is greater than `tempoBlockNumber`, the portal looks up `recentTempoBlockNumber` from EIP-2935 instead. The proof verifies the parent-hash chain from `tempoBlockNumber` to `recentTempoBlockNumber` internally, using Tempo headers included in the witness. This allows batch submission even when `tempoBlockNumber` has rotated out of the EIP-2935 window (roughly 8192 blocks), preventing the zone from being bricked after extended downtime.

`recentTempoBlockNumber` must be strictly greater than `tempoBlockNumber` when non-zero.

### Proof Requirements

The proof must validate:

1. The state transition from `prevBlockHash` to `nextBlockHash` is correct, and the final executed header number equals `nextZoneHeight`.
2. The zone committed to `tempoBlockNumber` via `TempoState`.
3. The zone's `tempoBlockHash` matches `anchorBlockHash` (direct), or the parent-hash chain from `tempoBlockNumber` to `anchorBlockNumber` is valid (ancestry).
4. `ZoneOutbox.lastBatch().withdrawalBatchIndex` equals `expectedWithdrawalBatchIndex`.
5. `ZoneOutbox.lastBatch().withdrawalQueueHash` matches the submitted `withdrawalQueueHash`.
6. Every zone block extends the preceding canonical header, every checkpoint-only block contains no operational work, and the final block ends with withdrawal finalization.
7. Every Tempo account and storage value used during full-block execution is proven against the active imported state root; missing witness data is rejected.
8. Deposit processing is correct: deposits are processed oldest-first and contiguously from `prevProcessedHash`, the output hash and number equal the final `ZoneInbox` state, and the processed hash equals the portal's `currentDepositQueueHash` read from Tempo state.
9. Token enablement is correct: the exact ordered `enabledTokens` suffix advances the authenticated token hash, tokens initialize before deposits, and the output count transition equals the inbox pre- and post-state.

For the first proof, `prevBlockHash == 0`, but the witness begins with zone block 1 on top of the canonical genesis header. Genesis is not included as a batch member.

The block beneficiary is committed by the canonical block header. Leader scheduling is validated by node and follower import rules rather than a prover public input, and the threshold certificate separately authorizes the complete settlement statement.

## Zone Precompiles

Every enabled TIP-20 token is exposed as a precompile. Encrypted-deposit verification is performed internally by the native `ZoneInbox`, not through separately callable precompiles.

### TIP-20 Token Precompile

Each enabled TIP-20 token is deployed as a precompile at the same address as on Tempo. The precompile implements the standard TIP-20 interface with privacy modifications:

- `balanceOf` is restricted to the account owner; `allowance` is restricted to its owner or spender.
- Transfer-family operations (`transfer`, `transferFrom`, `approve`) charge a fixed 100,000 gas.
- `mint` is restricted to `ZoneInbox`, `burn` is restricted to `ZoneOutbox`.

## Encrypted Deposit Cryptography

The native `ZoneInbox` performs the following cryptographic operations internally. They are consensus execution helpers, not separately addressable precompiles.

### Chaum-Pedersen Verification

```solidity
function verifyProof(
    bytes32 ephemeralPubX,
    uint8 ephemeralPubYParity,
    bytes32 sharedSecret,
    uint8 sharedSecretYParity,
    bytes32 sequencerPubX,
    uint8 sequencerPubYParity,
    ChaumPedersenProof calldata proof
) internal pure returns (bool valid);
```

Verifies that an ECDH shared secret was correctly derived from the sequencer's private key and an ephemeral public key, without exposing the private key. Used during [onchain decryption verification](#onchain-decryption-verification) of encrypted deposits. Verification charges 6,000 gas in addition to the inbox call's other costs.

Proof generation uses a deterministic, domain-separated nonce so that independently built versions of the same zone block contain identical `advanceTempo` calldata. For a counter starting at zero, the prover computes:

```
candidate = HMAC-SHA256(uint256_be(privSeq), "tempo-zone-chaum-pedersen-nonce-v1" || sec1_compressed(ephemeralPub) || sec1_compressed(pubSeq) || sec1_compressed(sharedSecretPoint) || uint32_be(counter))
k = OS2IP(candidate)
```

Here, `uint256_be` and `uint32_be` are fixed-width big-endian encodings, `sec1_compressed` and `sec1_uncompressed` are the 33-byte and 65-byte SEC1 point encodings respectively, and `OS2IP` interprets a byte string as a big-endian nonnegative integer. If `k` is not a valid nonzero secp256k1 scalar, the prover increments the counter and retries. The prover then computes `R1 = k*G`, `R2 = k*ephemeralPub`, `c = OS2IP(keccak256(sec1_uncompressed(G) || sec1_uncompressed(ephemeralPub) || sec1_uncompressed(pubSeq) || sec1_uncompressed(sharedSecretPoint) || sec1_uncompressed(R1) || sec1_uncompressed(R2))) mod n`, where `n` is the secp256k1 group order, and `s = k + c*privSeq`. The verifier reconstructs `R1 = s*G - c*pubSeq` and `R2 = s*ephemeralPub - c*sharedSecretPoint`, recomputes `c'`, and checks `c == c'`.

### AES-GCM Decryption

```solidity
function decrypt(
    bytes32 key,
    bytes12 nonce,
    bytes calldata ciphertext,
    bytes calldata aad,
    bytes16 tag
) internal pure returns (bytes memory plaintext, bool valid);
```

Performs AES-256-GCM decryption and authentication tag verification. Returns the decrypted plaintext and `true` if the tag validates, or empty bytes and `false` otherwise. Used during [onchain decryption verification](#onchain-decryption-verification) of encrypted deposits. Execution charges 1,000 gas plus 3 gas per byte of ciphertext and additional authenticated data, in addition to the inbox call's other costs.

HKDF-SHA256 key derivation (used to derive the AES key from the ECDH shared secret) is performed by the native inbox, which supplies empty AAD to the decrypt operation.

<br>

## Contracts and Interfaces

This section lists the key types and contract interfaces referenced throughout the spec. Only the essential functions are shown. Implementations may include additional view functions and events.

### Common Types

```solidity
struct WithdrawalBounceBackDeposit {
    address token;
    address to;
    uint128 amount;
}

struct Withdrawal {
    address token;
    bytes32 senderTag;          // keccak256(abi.encodePacked(sender, txHash, fallbackNonce))
    address to;
    uint128 amount;
    bytes32 memo;
    uint64 gasLimit;
    uint64 fallbackNonce;
    bytes callbackData;         // max 1KB
    bytes encryptedSender;      // ECDH-encrypted (sender, txHash), or empty
}

struct Deposit {
    address token;
    address sender;
    uint128 amount;
    address tempoRefundRecipient;
    uint256 keyIndex;
    DepositPayload encrypted;
}

struct DepositPayload {
    bytes32 ephemeralPubkeyX;
    uint8 ephemeralPubkeyYParity;
    bytes ciphertext;
    bytes12 nonce;
    bytes16 tag;
}

enum DepositType {
    WithdrawalBounceBack,
    Deposit
}

struct QueuedDeposit {
    DepositType depositType;
    bytes depositData;  // abi.encode(WithdrawalBounceBackDeposit) or abi.encode(Deposit)
    bool rejected;       // retained ABI field; does not bypass onchain verification
}

struct EnabledToken {
    address token;
    string name;
    string symbol;
    string currency;
}

struct DecryptionData {
    bytes32 sharedSecret;
    uint8 sharedSecretYParity;
    ChaumPedersenProof cpProof;
}

struct ChaumPedersenProof {
    bytes32 s;  // response
    bytes32 c;  // challenge
}

struct BlockTransition {
    bytes32 prevBlockHash;
    bytes32 nextBlockHash;
}

struct DepositQueueTransition {
    bytes32 prevProcessedHash;
    bytes32 nextProcessedHash;
    uint64 prevDepositNumber;
    uint64 nextDepositNumber;
}

struct TokenEnablementTransition {
    uint64 prevProcessedTokenCount;
    uint64 nextProcessedTokenCount;
}

struct TokenConfig {
    bool enabled;
    bool depositsActive;
}

address constant ZONE_FACTORY_ADDRESS = 0x5aF2000000000000000000000000000000000000;
bytes12 constant ZONE_PORTAL_PREFIX = 0x5AD000000000000000000000;
address constant ZONE_PORTAL_IMPL_ADDRESS = 0x5AD1000000000000000000000000000000000000;
address constant ZONE_VERIFIER_ADDRESS = 0x5a56000000000000000000000000000000000000;
address constant ZONE_MESSENGER_ADDRESS = 0x5A4d000000000000000000000000000000000000;

struct ZoneInfo {
    uint32 zoneId;
    address portal;
    bool accessMode;
    bool gatewayMode;
    address admin;
    address[] sequencers;
    uint8 threshold;
    address verifier;
    string rpcUrl;
}

struct LastBatch {
    bytes32 withdrawalQueueHash;
    uint64 withdrawalBatchIndex;
}
```

### IZoneFactory

```solidity
enum Role {
    None,
    Sequencer,
    Account,
    CallbackGateway,
    PauseGuardian
}

enum Capability {
    PausePortal,
    AccessPolicy
}

interface IZoneFactory {
    struct CreateZoneParams {
        address initialToken;
        bool accessMode;
        bool gatewayMode;
        address[] allowedAccounts;
        address[] zoneGateways;
        address admin;
        address[] sequencers;
        uint8 threshold;
        string rpcUrl;
    }

    event ZoneCreated(
        uint32 indexed zoneId, address indexed portal,
        address initialToken, bool accessMode, bool gatewayMode,
        address admin, address[] sequencers,
        uint8 threshold, address verifier
    );

    function owner() external view returns (address);
    function transferOwnership(address newOwner) external;
    function createZone(CreateZoneParams calldata params) external returns (uint32 zoneId, address portal);
    function nextZoneId() external view returns (uint32);
    function zones(uint32 zoneId) external view returns (ZoneInfo memory);
    function isZonePortal(address portal) external view returns (bool);
}
```

### IZonePortal

```solidity
interface IZonePortal {
    // Events
    event DepositMade(
        bytes32 indexed newCurrentDepositQueueHash,
        address indexed sender,
        address token,
        uint128 netAmount,
        uint128 fee,
        uint256 keyIndex,
        bytes32 ephemeralPubkeyX,
        uint8 ephemeralPubkeyYParity,
        bytes ciphertext,
        bytes12 nonce,
        bytes16 tag,
        address tempoRefundRecipient,
        uint64 depositNumber
    );
    event BatchSubmitted(
        uint64 indexed withdrawalBatchIndex,
        uint256 indexed withdrawalQueueIndex,
        bytes32 nextProcessedDepositQueueHash,
        bytes32 nextBlockHash,
        bytes32 withdrawalQueueHash,
        uint64 lastProcessedDepositNumber,
        uint64 lastProcessedEnabledTokenCount
    );
    event WithdrawalProcessed(
        address indexed to,
        bytes32 indexed senderTag,
        address token,
        uint128 amount,
        bool callbackSuccess
    );
    event WithdrawalBounceBack(
        bytes32 indexed newCurrentDepositQueueHash,
        uint64 indexed fallbackNonce,
        address token,
        uint128 amount,
        uint64 depositNumber
    );
    event DepositBounceBack(
        address indexed tempoRefundRecipient, address token,
        uint128 amount, uint128 bouncebackFee
    );
    event DepositBounceBackPending(
        address indexed tempoRefundRecipient, address token,
        uint128 amount, uint128 bouncebackFee
    );
    event RefundClaimed(address indexed recipient, address indexed token, uint128 amount);
    event SequencerSetUpdated(uint64 indexed nonce, uint8 threshold, address[] sequencers);
    event LeaderUpdated(
        address indexed previousLeader, address indexed newLeader,
        uint64 indexed epoch, uint64 activationTempoBlock
    );
    event AdminTransferStarted(address indexed currentAdmin, address indexed pendingAdmin);
    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);
    event SequencerEncryptionKeyUpdated(
        bytes32 x, uint8 yParity, address pubkey, uint256 keyIndex, uint64 activationBlock
    );
    event ZoneGasRateUpdated(uint128 zoneGasRate);
    event MaxTempoGasRateUpdated(uint128 maxTempoGasRate);
    event BouncebackGasUpdated(uint64 bouncebackGas);
    event TokenEnabled(address indexed token, string name, string symbol, string currency);
    event DepositsPaused(address indexed token);
    event DepositsResumed(address indexed token);
    event PortalPaused(address indexed account);
    event PortalResumed(address indexed account);
    event AbdicationScheduled(Capability indexed capability, uint64 effectiveAt);
    event RoleUpdated(address indexed account, Role prev, Role next);
    event EnforcementModesUpdated(bool accessMode, bool gatewayMode);

    error NotSequencer();
    error NotAdmin();
    error NotPauseAuthority();
    error CapabilityAbdicated(Capability capability);
    error AbdicationAlreadyScheduled(Capability capability);
    error PortalIsPaused();
    error NotPendingAdmin();
    error InvalidProof();
    error InvalidTempoBlockNumber();
    error CallbackRejected();
    error EncryptionKeyExpired(uint256 keyIndex, uint64 activationBlock, uint64 supersededAtBlock);
    error InvalidEncryptionKeyIndex(uint256 keyIndex);
    error NoEncryptionKeySet();
    error NoEncryptionKeyAtBlock(uint64 blockNumber);
    error InvalidEphemeralPubkey();
    error InvalidCiphertextLength(uint256 actual, uint256 expected);
    error InvalidProofOfPossession();
    error DepositTooSmall();
    error DepositBlockCapacityExceeded(uint64 maximum);
    error TokenEnablementBlockCapacityExceeded(uint64 maximum);
    error TokenMetadataTooLong();
    error GasFeeRateTooHigh();
    error TokenNotEnabled();
    error DepositsNotActive();
    error TokenAlreadyEnabled();
    error InvalidBouncebackRecipient();
    error InvalidDepositTransition();
    error InvalidTokenEnablementTransition();
    error InvalidSequencerSet();
    error SequencerConfigurationUnchanged();
    error InvalidQuorumCertificate();
    error InvalidLeader();
    error ActiveLeaderRemoved();
    error LeaderAlreadyUpdatedThisBlock();
    error StaleLeadershipEpoch(uint64 expected, uint64 actual);

    function FIXED_DEPOSIT_GAS() external view returns (uint64);
    function MAX_UNPROCESSED_DEPOSITS() external view returns (uint64);
    function MAX_UNPROCESSED_TOKEN_ENABLEMENTS() external view returns (uint64);
    function MAX_TOKEN_METADATA_BYTES() external view returns (uint256);
    function MAX_WITHDRAWAL_GAS_LIMIT() external view returns (uint64);
    function MAX_GAS_FEE_RATE() external view returns (uint128);

    // Token management
    function enableToken(address token) external;
    function pauseDeposits(address token) external;
    function resumeDeposits(address token) external;
    function paused() external view returns (bool);
    function pauseExpiry() external view returns (uint64);
    function abdicationEffectiveAt(Capability capability) external view returns (uint64);
    function pause() external;
    function resume() external;
    function abdicate(Capability capability) external;
    function isTokenEnabled(address token) external view returns (bool);
    function areDepositsActive(address token) external view returns (bool);
    function tokenConfig(address token) external view returns (TokenConfig memory);
    function enabledTokenCount() external view returns (uint256);
    function lastProcessedEnabledTokenCount() external view returns (uint64);
    function enabledTokenAt(uint256 index) external view returns (address);
    function tokenEnablementHash() external view returns (bytes32);

    // Access and callback configuration
    function isAccessEnforced() external view returns (bool);
    function setAccessMode(bool enforced) external; // admin-only
    function isGatewayOpen() external view returns (bool);
    function setGatewayMode(bool enforced) external; // admin-only
    function hasRole(address account, Role role) external view returns (bool);
    function setAllowedAccount(address account, bool allowed) external; // admin-only
    function setGateway(address account, bool allowed) external; // admin-only

    // Zone RPC endpoint. Published on-chain so clients can discover how to reach the zone.
    event RpcUrlUpdated(string rpcUrl);
    function rpcUrl() external view returns (string memory);
    function setRpcUrl(string calldata rpcUrl) external; // sequencer-only

    // Deposits
    /// @dev Closed access requires caller and refund-recipient membership, except that an
    ///      an account with the CallbackGateway role may make a synchronous callback return
    ///      while gateway enforcement is active.
    ///      The encrypted zone recipient need not be an allowed Tempo account.
    function deposit(
        address token, uint128 amount, uint256 keyIndex,
        DepositPayload calldata encrypted, address tempoRefundRecipient
    ) external returns (bytes32 newCurrentDepositQueueHash);
    function depositEncrypted(
        address token, uint128 amount, uint256 keyIndex,
        DepositPayload calldata encrypted, address tempoRefundRecipient
    ) external returns (bytes32 newCurrentDepositQueueHash);
    function calculateDepositFee() external view returns (uint128 fee);
    function calculateBouncebackFee() external view returns (uint128 fee);
    function bouncebackGas() external view returns (uint64);
    function setBouncebackGas(uint64 newBouncebackGas) external;
    function depositCount() external view returns (uint64);
    function lastProcessedDepositNumber() external view returns (uint64);

    // Batch submission
    function submitBatch(
        uint64 tempoBlockNumber, uint64 recentTempoBlockNumber,
        BlockTransition calldata blockTransition,
        DepositQueueTransition calldata depositQueueTransition,
        TokenEnablementTransition calldata tokenEnablementTransition,
        bytes32 withdrawalQueueHash, bytes calldata verifierConfig, bytes calldata proof,
        uint256 zoneHeight, bytes[] calldata signatures
    ) external;

    // Withdrawal processing
    function processWithdrawals(Withdrawal[] calldata withdrawals, bytes32 remainingQueue) external;

    // Refund registry (deposit bounce-back transfers that reverted on Tempo, e.g.
    // because the recipient was rejected by the token's TIP-403 policy at refund time)
    /// @notice Outstanding refundable balance for a recipient on a given token.
    function refunds(address token, address owner) external view returns (uint128);
    /// @notice Claim outstanding refunds in `token` for `msg.sender`. Reverts if the
    ///         underlying TIP-20 transfer reverts (e.g. policy still forbids the recipient).
    function claimRefund(address token) external returns (uint128 amount);

    // Active sequencer-set management
    function setSequencerSet(address[] calldata sequencers, uint8 threshold) external;
    function sequencerSetVersion() external view returns (uint64);
    function sequencerThreshold() external view returns (uint8);
    function zoneHeight() external view returns (uint256);
    function isSequencer(address account) external view returns (bool);
    function sequencerCount() external view returns (uint256);
    function sequencerAt(uint256 index) external view returns (address);

    // Active block-production leader
    function leader() external view returns (address);
    function leaderEpoch() external view returns (uint64);
    function leaderActivationTempoBlock() external view returns (uint64);
    function setLeader(address newLeader, uint64 expectedEpoch) external;

    // Admin management
    function transferAdmin(address newAdmin) external;
    function acceptAdmin() external;

    function setZoneGasRate(uint128 _zoneGasRate) external;
    function zoneGasRate() external view returns (uint128);
    function setMaxTempoGasRate(uint128 _maxTempoGasRate) external;
    function maxTempoGasRate() external view returns (uint128);

    // Encryption keys
    function setSequencerEncryptionKey(bytes32 x, uint8 yParity, uint8 popV, bytes32 popR, bytes32 popS) external;
    function sequencerEncryptionKey()
        external view returns (bytes32 x, uint8 yParity, address pubkey);

    function encryptionKeyCount() external view returns (uint256);
    function encryptionKeyAt(uint256 index) external view returns (EncryptionKeyEntry memory entry);
    function encryptionKeyAtBlock(uint64 tempoBlockNumber)
        external view returns (bytes32 x, uint8 yParity, uint256 keyIndex);
    function isEncryptionKeyValid(uint256 keyIndex) external view returns (bool valid, uint64 expiresAtBlock);

    // State
    function zoneId() external view returns (uint32);
    function messenger() external view returns (address);
    function admin() external view returns (address);
    function pendingAdmin() external view returns (address);

    function verifier() external view returns (address);
    function blockHash() external view returns (bytes32);
    function currentDepositQueueHash() external view returns (bytes32);
    function withdrawalBatchIndex() external view returns (uint64);
    function lastSyncedTempoBlockNumber() external view returns (uint64);
    function withdrawalQueueHead() external view returns (uint256);
    function withdrawalQueueTail() external view returns (uint256);
    function withdrawalQueueSlot(uint256 queueIndex) external view returns (bytes32);
}
```

### IZoneMessenger

```solidity
interface IZoneMessenger {
    function relayMessage(
        uint32 zoneId, address token, bytes32 senderTag, address target,
        uint128 amount, uint64 gasLimit, bytes calldata data
    ) external;
}
```

The callback payload is opaque to the outbox and messenger and is interpreted by the configured ZoneGateway.

### IWithdrawalReceiver

```solidity
interface IWithdrawalReceiver {
    function onWithdrawalReceived(
        uint32 zoneId, address sourcePortal, bytes32 senderTag,
        address token, uint128 amount, bytes calldata callbackData
    ) external returns (bytes4);
}
```

The receiver must return `IWithdrawalReceiver.onWithdrawalReceived.selector` to confirm successful handling.

### ITempoState

Address: `0x1c00000000000000000000000000000000000000`

```solidity
interface ITempoState {
    event TempoBlockFinalized(bytes32 indexed blockHash, uint64 indexed blockNumber, bytes32 stateRoot);

    error InvalidTimestamp();
    error OnlyZoneInbox();
    error StaticCallNotAllowed();

    function tempoBlockHash() external view returns (bytes32);
    function tempoBlockNumber() external view returns (uint64);

    /// @notice Finalize consecutive Tempo headers. Only callable by ZoneInbox.
    /// @dev State-changing; static calls are rejected.
    function finalizeTempo(bytes[] calldata headers) external;
}
```

### IZoneInbox

Address: `0x1c00000000000000000000000000000000000001`

```solidity
interface IZoneInbox {
    /// @notice A canonical deposit queued by the portal for processing on the zone.
    /// @dev WithdrawalBounceBack entries are internal. Every Deposit entry consumes
    ///      one DecryptionData item and performs onchain verification.
    struct QueuedDeposit {
        DepositType depositType;
        bytes depositData; // abi.encode(WithdrawalBounceBackDeposit) or abi.encode(Deposit)
        bool rejected; // does not bypass onchain verification
    }

    event TempoAdvanced(
        bytes32 indexed tempoBlockHash, uint64 indexed tempoBlockNumber,
        uint256 depositsProcessed, bytes32 newProcessedDepositQueueHash,
        uint64 lastProcessedDepositNumber,
        uint64 lastProcessedEnabledTokenCount
    );
    event DepositProcessed(
        bytes32 indexed depositHash, address indexed sender, address indexed to,
        address token, uint128 amount, bytes32 memo
    );
    event DepositFailed(
        bytes32 indexed depositHash, address indexed sender, address token, uint128 amount
    );
    /// @notice Emitted when a withdrawal-bounce-back deposit (synthesized by the portal
    ///         with `tempoRefundRecipient == address(0)`) was minted successfully to the
    ///         original `zoneFallbackRecipient` on the zone.
    event WithdrawalBounceBackProcessed(
        address indexed zoneFallbackRecipient, address token, uint128 amount
    );
    /// @notice Emitted when the zone-side refund mint for a withdrawal-bounce-back
    ///         deposit reverted (e.g. zone TIP-403 policy forbids the recipient) and
    ///         the amount was credited to the inbox refund registry, claimable via
    ///         `claimRefund(token)`.
    event WithdrawalBounceBackPending(
        address indexed zoneFallbackRecipient, address token, uint128 amount
    );
    /// @notice Emitted when a recipient claims an outstanding withdrawal-bounce-back refund.
    event RefundClaimed(address indexed recipient, address indexed token, uint128 amount);
    event TokenEnabled(address indexed token, string name, string symbol, string currency);

    error InvalidTokenEnablementHash();
    error OnlySequencer();

    function processedDepositQueueHash() external view returns (bytes32);
    function processedDepositNumber() external view returns (uint64);
    function processedTokenEnablementHash() external view returns (bytes32);
    function processedEnabledTokenCount() external view returns (uint64);

    /// @notice Authenticate Tempo ancestry without processing portal work.
    /// @dev Only callable by the zone system caller (address(0)).
    function advanceTempoHeaders(bytes[] calldata headers) external;

    /// @notice Advance Tempo and process the complete portal-work suffix.
    /// @dev Only callable by the zone system caller (address(0)).
    function advanceTempo(
        bytes calldata header, QueuedDeposit[] calldata deposits, DecryptionData[] calldata decryptions,
        EnabledToken[] calldata enabledTokens
    ) external;

    // Refund registry (withdrawal bounce-back mints that reverted on the zone, e.g.
    // because the recipient was rejected by the zone-side TIP-403 policy at mint time)
    /// @notice Outstanding refundable balance for a recipient on a given token.
    /// @dev Only callable directly by `owner` or an active sequencer.
    function refunds(address token, address owner) external view returns (uint128);
    /// @notice Claim outstanding refunds in `token` for `msg.sender`. Reverts if the
    ///         underlying mint reverts (e.g. policy still forbids the recipient).
    function claimRefund(address token) external returns (uint128 amount);
}
```

`EnabledToken` carries the token address and exact metadata bytes committed by `ZonePortal.tokenEnablementHash` for direct activation of zone-side TIP-20 precompiles by `ZoneInbox`. The array passed to `advanceTempo` is untrusted until the Inbox verifies that applying the canonical hash transition from `processedTokenEnablementHash` reaches the portal commitment at the imported Tempo state. At most 8 enablements may remain outstanding, including work deferred across checkpoint-only blocks. Each `name`, `symbol`, and `currency` is limited to 31 encoded bytes.

### IZoneOutbox

Address: `0x1c00000000000000000000000000000000000002`

```solidity
interface IZoneOutbox {
    function MAX_CALLBACK_DATA_SIZE() external view returns (uint256);
    function MAX_WITHDRAWAL_GAS_LIMIT() external view returns (uint64);
    function WITHDRAWAL_BASE_GAS() external view returns (uint64);

    event WithdrawalRequested(
        uint64 indexed withdrawalIndex, address indexed sender, address token, address to,
        uint128 amount, uint128 fee, bytes32 memo, uint64 gasLimit,
        uint64 fallbackNonce, bytes data, bytes revealTo
    );
    event TempoGasRateUpdated(uint128 tempoGasRate);
    event MaxWithdrawalsPerBlockUpdated(uint256 maxWithdrawalsPerBlock);
    event BatchFinalized(bytes32 indexed withdrawalQueueHash, uint64 withdrawalBatchIndex);

    error InvalidFallbackRecipient();
    error CallbackDataTooLarge();
    error GasFeeRateTooHigh();
    error TokenNotEnabled();
    error TransferFailed();
    error OnlySequencer();
    error InvalidBlockNumber();
    error TooManyWithdrawalsThisBlock();
    error InvalidRevealTo();
    error InvalidCurrentTxHash();
    error InvalidEncryptedSenderCount(uint256 actual, uint256 expected);
    error InvalidEncryptedSenderLength(uint256 actual, uint256 expected);
    error GasLimitTooHigh();
    error OnlyZoneInbox();

    function tempoGasRate() external view returns (uint128);
    function nextWithdrawalIndex() external view returns (uint64);
    function lastFallbackNonce() external view returns (uint64);
    function lastBatch() external view returns (LastBatch memory);
    function pendingWithdrawalsCount() external view returns (uint256);
    function maxWithdrawalsPerBlock() external view returns (uint32);

    function setTempoGasRate(uint128 _tempoGasRate) external;
    function setMaxWithdrawalsPerBlock(uint32 _maxWithdrawalsPerBlock) external;
    /// @notice Compute the withdrawal fee for the current Tempo gas rate. Reads
    ///         zone-side `tempoGasRate` and snapshots it onto the queued withdrawal
    ///         at request time.
    function calculateWithdrawalFee(uint64 gasLimit) external view returns (uint128);

    function requestWithdrawal(
        address token, address to, uint128 amount, bytes32 memo,
        uint64 gasLimit, address zoneFallbackRecipient, bytes calldata data
    ) external;

    function requestWithdrawal(
        address token, address to, uint128 amount, bytes32 memo,
        uint64 gasLimit, address zoneFallbackRecipient, bytes calldata data, bytes calldata revealTo
    ) external;

    function enqueueDepositBounceBack(
        address token, uint128 amount, address tempoRefundRecipient
    ) external;

    function consumeFallbackRecipient(uint64 fallbackNonce)
        external returns (address zoneFallbackRecipient);

    function finalizeWithdrawalBatch(uint256 count, uint64 blockNumber, bytes[] calldata encryptedSenders)
        external returns (bytes32 withdrawalQueueHash);
}
```

### TIP-403 Registry

Deployed at the same address as on Tempo. Read-only on the zone. Its read methods execute Tempo's registry logic over raw L1 policy storage at the finalized `TempoState.tempoBlockNumber` anchor. Zone-side TIP-20 transfers call this automatically.

<br>

## Network Upgrades and Hard Fork Activation

Zones activate hard fork upgrades in lockstep with Tempo. A zone block's timestamp selects its execution rules. The node MUST NOT produce a block under new rules until the finalized Tempo chain has activated the same fork, even when the block imports an older Tempo checkpoint during catch-up.

At the T9 boundary, Tempo copies the complete runtime bytecode from hardfork-specified portal implementation, verifier, and messenger source deployments to their fixed protocol-managed addresses, equivalent to `EXTCODECOPY`. The ZoneFactory owner cannot invoke these copies or replace the installed runtimes. Any later replacement requires a Tempo hardfork and uses the same copy operation at that hardfork boundary. Replacing the portal implementation upgrades every portal proxy and therefore MUST preserve the portal storage layout.

Zone nodes and provers select execution rules from the zone block timestamp and the Tempo fork schedule compiled into the implementation. No zone-specific protocol version is encoded in the zone block header or prover witness. A node that does not support the active Tempo fork must halt rather than produce a block under stale rules.

A settlement batch MAY contain zone blocks from both sides of a Tempo hard fork. Crossing a hard fork does not itself create a batch boundary. The prover MUST execute every zone block under the Tempo rules selected by that block's timestamp, including historical rules for blocks before the fork. Batch submission uses the portal ABI, settlement-attestation format, verifier, and accepted prover image active on Tempo when the batch is submitted; the active prover image MUST therefore support every historical fork represented in the batch.

No onchain action is required from zone operators. Operators upgrade their zone node binary and prover program before the fork. When the fork Tempo block arrives, the node activates new rules automatically. Runtime replacements are consensus changes coordinated with that activation.

If the fork changes zone predeploy behavior, the zone node injects new bytecode at the predeploy addresses before `advanceTempo` executes in the first post-fork zone block.

If the operator does not upgrade before the fork, the zone node detects that it does not support the active Tempo fork and halts cleanly. If the node is upgraded but the prover is stale, zone execution continues but settlement pauses until the new prover is installed. In both cases, user funds remain safe in the portal.
