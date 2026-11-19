---
id: TIP-XXXX
title: Org-Bound Accounts
description: A new configurable account can commit to a Zone org in its address, so an org's provisioner can add it without any signature from the account, and nobody can add an account that wasn't created for that org.
authors: @Slokh
status: Draft
related: TIP-1180, TIP-1107, TIP-1154, TIP-1164, [tempoxyz/tempo#9436](https://github.com/tempoxyz/tempo/pull/9436)
protocolVersion: TBD
---

# TIP-XXXX: Org-Bound Accounts

## Abstract

A new configurable account can commit to one org on one Zone through its TIP-1107 salt. The org's provisioner, which the org admin designates, adds such an account with `claimMembers` by revealing the inputs to its address. The account signs nothing, and only accounts whose address commits to that org can be added this way. Org admins can then add only predeployed Zone contracts without consent, and existing accounts join through an invite they accept. The commitment covers the first join only; later moves follow TIP-1180.

## Motivation

Under [TIP-1180](https://github.com/tempoxyz/tempo/pull/9436), an org admin adds any account in no org with `addMembers`, without asking the account. Membership lets the org's admin and readers read the account's balances, nonces and keychain state, and lets the admin freeze it. Whoever can add an account can therefore read it.

Shared Zones onboard users through wallet providers that create wallets for many companies. An org needs each new wallet in the org before it receives funds. The wallet provider must not sign on behalf of a user's wallet to do that, and many wallets are created through server-side APIs with no user present to sign. A per-user consent signature fails both requirements.

Giving the provider TIP-1180 admin rights, or a narrower role that only calls `addMembers`, meets those requirements but lets the provider add any account in no org, including wallets it never created for that org. Restricting `addMembers` to fresh accounts (nonce 0, no balance) narrows this to new wallets, but an adder can still take another org's new wallet before that org adds it.

[TIP-1164](https://github.com/tempoxyz/tempo/pull/9114) derives each member address from a salt that mixes in the Zone and the org, so a member account is new and can't be reused. This TIP applies the same idea to TIP-1180 membership: the address names the one org that may claim it, so adding it needs no signature from the account, and adding any other account is impossible.

| Option | New wallet joins without an account signature | Adder can't add other wallets |
|---|---|---|
| TIP-1180 admin-only `addMembers` | Yes | No |
| Members-only role for the provider | Yes | No |
| `addMembers` limited to fresh accounts | Yes | No: adders race for new wallets |
| Account signs `joinOrg` | No | Yes |
| This TIP | Yes | Yes |

## Assumptions

- TIP-1107, TIP-1154 and TIP-1180, including org readers, are active.
- The account's initial owners, or their wallet provider, chose its salt. An account whose salt commits to an org was created for that org, and this TIP treats creation as agreement to join it.
- Wallet providers create Zone wallets as configurable accounts. A primitive key's address can't commit to an org, so it joins only through an [invite](#existing-accounts).
- Whoever chooses a salt can search for a colliding configuration in roughly 2^80 work, as TIP-1107's [counterfactual funding](./tip-1107.md#counterfactual-funding) describes. This TIP adds no protection against the party that chose the salt.
- The registrar is trusted as in TIP-1180.

---

# Specification

## Overview

An **org-bound account** is a TIP-1107 configurable account whose salt is derived from a Zone ID, an org ID and a random blinding value. Anyone who knows those inputs can show which org the account was created for. Anyone who doesn't sees a random salt, including on Tempo if the account registers there.

| Role | Can |
|---|---|
| Org admin | Designate provisioners, invite existing accounts, add Zone contracts |
| Provisioner | Add org-bound accounts that commit to its org |
| Account | Accept an invite with a transaction its owners sign |
| Registrar | Everything TIP-1180 allows, and add any account to any org |

1. The wallet derives the account's address from an org-bound salt. No transaction is needed.
2. A provisioner calls `claimMembers` on the Zone with the address's inputs. `ZoneIdentity` recomputes the address and adds it to the org.
3. From then on the account is an ordinary TIP-1180 member. The admin can freeze or remove it, and it joins another org only through an invite.

## Mechanics

### Deriving an org-bound address

The wallet chooses a 32-byte `userSalt` and a 32-byte random `blinding`, and computes:

```text
orgCommit = keccak256("tempo:org-bound:org" || uint64(orgId) || blinding)
salt      = keccak256("tempo:org-bound:salt" || uint32(zoneId) || orgCommit || userSalt)
account   = TIP-1107 address derivation over (salt, threshold, owners)
```

Encodings follow [TIP-1107 address derivation](./tip-1107.md#address-derivation): raw concatenation, big-endian integers, owners sorted. `zoneId` is `ZonePortal.zoneId()`. The result is an ordinary TIP-1107 address, and Tempo and Zones treat it like any other configurable account.

`blinding` keeps `orgCommit` from revealing the org when the salt is published, for example in TIP-1107's registration event. Wallets MUST draw it from a secure random source and keep it with the configuration.

### Designating provisioners

The org admin calls `setProvisioner(orgId, provisioner, allowed)`. An org may have several provisioners. Like TIP-1180 readers, entries are stored per admin epoch, so replacing the org's admin revokes every provisioner at once.

### Claiming accounts

A provisioner, the org admin or the registrar calls `claimMembers(orgId, claims)`. For each claim, `ZoneIdentity`:

1. Recomputes `orgCommit`, `salt` and `account` from `orgId`, the Zone's own `zoneId` and the claim's `userSalt`, `blinding`, `threshold` and `owners`.
2. Applies TIP-1107's configuration rules to `threshold` and `owners`, and rejects any address TIP-1107 forbids.
3. Requires `account` to be in no org and never claimed.
4. Writes the member slot `{org: orgId, frozen: false}`, sets `claimed[account]`, and emits `MemberClaimed` and TIP-1180's `MemberUpdated`.

If any claim fails, the call reverts and adds none. The caller signs only its own transaction. The account need not exist on the Zone, hold funds or be registered on Tempo.

`claimed[account]` stays set after the account leaves its org, so a provisioner can't re-add an account its admin removed.

### Admin adds

From this TIP's activation, an org admin's `addMembers` accepts only accounts that have code on the Zone. Zones disable contract creation, so these are the Zone's predeployed contracts, such as routers and escrows, which have no key to sign with. Otherwise `addMembers` reverts with `NotAContract`. The registrar may still add any account to any org, for migrations.

### Existing accounts

An account that is not org-bound, including a primitive key or an account upgraded under TIP-1113, joins through an invite:

1. The org admin or a provisioner calls `invite(orgId, accounts, allowed)`.
2. The account calls `acceptInvite(orgId)` in a transaction its owners sign. `ZoneIdentity` requires an open invite and the account to be in no org, then adds it and clears the invite.

The same path moves a member to another org after its current admin removes it.

### Leaving

Unchanged from TIP-1180: only the account's org admin can remove it.

## Interfaces

Additions to `IZoneIdentity` at `0x1c00000000000000000000000000000000000003`:

```solidity
struct Owner {
    address owner;
    uint8 weight;
}

struct Claim {
    bytes32 userSalt;
    bytes32 blinding;
    uint8 threshold;
    /// Sorted by owner address, as TIP-1107 requires.
    Owner[] owners;
}

/// Org admin. Designates or removes a provisioner for the current admin epoch.
function setProvisioner(uint64 orgId, address provisioner, bool allowed) external;

/// Provisioner, org admin or registrar. Adds each account derived for orgId on this Zone and
/// returns the addresses in claim order. Reverts, adding none, if any claim fails.
function claimMembers(uint64 orgId, Claim[] calldata claims) external returns (address[] memory accounts);

/// Org admin or provisioner. Opens or closes invites for existing accounts.
function invite(uint64 orgId, address[] calldata accounts, bool allowed) external;

/// The caller joins orgId through an open invite.
function acceptInvite(uint64 orgId) external;

function isProvisioner(uint64 orgId, address provisioner) external view returns (bool);
function claimed(address account) external view returns (bool);

event ProvisionerUpdated(uint64 indexed orgId, address indexed provisioner, bool allowed);
event MemberClaimed(address indexed account, uint64 indexed orgId, address provisioner);
event InviteUpdated(uint64 indexed orgId, address indexed account, bool allowed);

error AlreadyClaimed(address account);
error NoInvite(uint64 orgId, address account);
error NotAContract(address account);
```

View and event visibility follow TIP-1180. Storage layout, gas and selectors are not yet specified.

# Compatibility

| Integration | What changes |
|---|---|
| Wallet providers | Derive Zone wallets with an org-bound salt, store `userSalt` and `blinding` with the configuration, and submit `claimMembers` from the provisioner key when creating the wallet |
| Org admins | Call `setProvisioner` once per provisioner. Use `invite` for existing accounts and `addMembers` only for Zone contracts |
| Existing TIP-1180 members | Unaffected |
| Bulk migrations of existing accounts | Go through the registrar, or the accounts accept invites |
| TIP-1107 and TIP-1154 | Unchanged. An org-bound account is an ordinary configurable account on Tempo and on Zones |

# Observability

- `MemberClaimed(account, orgId, provisioner)`: which provisioner added which account, so an org admin can audit its provisioners.
- `ProvisionerUpdated` and `InviteUpdated`: who may add accounts to an org.
- TIP-1180's `MemberUpdated` is still emitted for every membership change.

# Threat Model

The most consequential attack this TIP removes is an adder putting someone else's account into its org to read or freeze it.

| Actor | Controls | Can't | Enforced by |
|---|---|---|---|
| Provisioner | Which accounts bound to its org are claimed, and when | Add an account not derived for its org, add to another org, or re-add a removed account | Address recomputation, per-org provisioner check, `claimed` |
| Org admin | Provisioners, invites, contract adds, freezes, removals | Add a keyed account that neither commits to the org nor accepts an invite | `addMembers` code check, `acceptInvite` sender |
| Another org's admin or provisioner | Its own org | Claim an account bound to this org | Address recomputation |
| Salt chooser, usually the wallet provider | Which org a new account commits to | Change it after creation | Address derivation |
| Registrar | Every org | Nothing new; trusted as in TIP-1180 | None |

Residual risks:

- A wallet provider that is a provisioner for several orgs chooses which org each new wallet commits to. An org that must control this claims with its own key and designates no outside provisioner.
- The party that chose the salt can search for a colliding configuration in about 2^80 work, as in TIP-1107.
- `claimMembers` reveals `blinding` and the initial owners to the Zone sequencer and to whoever can read the call. They are never published on Tempo.
- The account's owners don't sign the claim. Creation counts as agreement, so users who must give explicit consent need a wallet without an org-bound salt.

# Invariants

1. An account with no Zone code becomes a member of org X only through `claimMembers` with inputs that derive it for X on this Zone, through `acceptInvite` sent by the account, or through the registrar.
2. `claimMembers` never changes the membership of an account already in an org.
3. Once `claimed[account]` is set, it stays set.
4. After `setOrgAdmin`, no provisioner designated under an earlier admin can claim.
5. An address derived for org X on Zone Z can't be claimed into any other org or on any other Zone.

Tests must cover a claim with a wrong `blinding`, `orgId` or `zoneId`; a claim for an account already in another org; a re-claim after removal; a provisioner after an admin change; `addMembers` on an account with no code; and `acceptInvite` without an invite.
