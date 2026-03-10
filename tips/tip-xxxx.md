---
id: TIP-XXXX
title: Fee Recipient from Validator Config V2
description: Validators declare a fee recipient address in ValidatorConfigV2; the node reads it and passes it to the payload builder.
authors: @superfluffy
status: Draft
related: TIP-1017
protocolVersion: TBD
---

# TIP-XXXX: Fee Recipient from Validator Config V2

## Abstract

Proposers use the `feeRecipient` field added to validator entries in [TIP-1017](./tip-1017.md).
When a validator proposes a block, the node reads this on-chain field and uses it as the fee recipient in the payload builder.
The command line flag `--consensus.fee-recipient` is removed.

## Proposal

1. Nodes, when building blocks to be proposed, use the
  `ValidatorConfigV2.Validator.feeRecipient` field of their `Validator` entry
   at the chain state of the notarized parent block.
2. The state of the notarized (not finalized) block is used because:
    + the state must be available to propose a block.
    + because Tempo consensus uses a VRF to determine the next leader, a node
      can be elected leader several blocks in a row. Waiting for the fee receipient
      rotation to be actived by a finalized block would make it non-deterministic.
3. Remove the `--consensus.fee-recipient` command line argument to provide a
   single source of truth and make compliance easier.

## Motivation

For compliance reasons, operators wish to separate every day node ops from treasury
management. In the context of running a validator, treasury management includes
the `feeRecipient` field of entries in the smart contract, and the `ValidatorConfigV2.setFeeRecipient`
contract call. Regular node operations include all other calls.

Currently, an infrastructure engineer has complete control over where fees are
sent by using `--consensus.fee-recipient` command line argument on the tempo binary.
With this TIP, treasury management can instead be gated behind higher priviledge
requirements (for example, requiring a higher multisig threshold), while keeping
every day ops more manageable (by requiring a lower multisig threshold).

## Node Behaviour

When proposing a block, the node determines its fee recipient as follows:

1. Read its entry `v` from the ValidatorConfigV2 using `ValidatorConfig2.validatorByPublicKey`
   at the chain state of the proposal's parent block.
2. The public key is determined from the ed25519 signing key passed to the node
   at startup.
3. Use `v.feeRecipient` of its entry in `TempoPayloadBuilderAttributes`.

## Relationship with subblock building?

TBD.

## Migration

This TIP will be activated in a future hardfork (TBD). The command line option
`--consensus.fee-recipient` will be deprecated but still be present during this
hardfork period and removed in a subsequent hardfork (TBD). The node will behave
like so, with the contract value taking priority if set.

1. Use `v.feeRecipient` if set to a value that is *not* the zero address `0x0`.
2. If `v.feeRecipient` is set to the zero address `0x0`, use `--consensus.fee-recipient`.
3. `--consensus.fee-recipient` will retain a default value of `0x0`.
