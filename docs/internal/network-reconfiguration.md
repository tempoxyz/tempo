# Network reconfiguration

This document defines how the Tempo network reconfigures its set of active
validators through the a distribute key generation ceremony.

## Definitions and network state

Tempo is running Simplex consensus using the commonwarexyz stack with
BLS12-381 threshold signatures. For a high level overview of the protocol,
see [1] and [2]. Node-to-node communication is done using direct p2p, with all
peer identities and socket addresses known. Commonwarexyz calls this scheme
"authenticated lookup p2p" [3]. In tempo, peers are identified by their ed25519
public key.

The network state evolves in epochs, where epochs are numbered 0, 1, 2, ... and
where each epoch has the same length of blocks `E` defined at genesis. For a
given `E`, epoch 0 runs from blocks 0 to E-1, epoch 1 from E to 2E-1, epoch 2
from 2E to 3E-1 and so on. During an epoch, the network runs a so-called DKG
(dynamic key generation) ceremony, transitioning to the new epoch with the
result of this DKG ceremony.

The state of a network (and thus the outcome of a DKG ceremony) for a given
epoch is then defined by:

1. the public threshold key polynomial;
2. the set of private threshold key shares (one per validator);
3. the list `[ed25519-public-key]` of public ed25519 keys uniquely identifying
   each validator, socket-address)`.

Before genesis, it is expected that some other process generates the initial
public threshold key polynomial and its corresponding set of private threshold
key shares (one per validator). This process should be done such that each
private key share is known to its owning validator.

At genesis then, the network is launched with

1. the pre-generated public polynomial,
2. the set of private key shares corresponding to the polynomial,
3. a list `(ed25519-public-key, socket-address)` pairs to make the identity
   and contact details of all peers known,
4. and the the `epoch_length`, a fixed number setting how many blocks are
   generated before a new epoch is started.

It should be noted that the initial polynomial's constant term will stay
constant across all DKG resharing ceremonies. This means that the initial
public polynomial can be used to verify certificates of any epoch.

Note that for the purpose of the ceremony outcome, only the ed25519 public keys
are relevant. The socket addresses are also noted here as a side-effect of the
choice of P2P network, binding key and address closely together.

[1]: https://docs.rs/commonware-consensus/0.0.63/commonware_consensus/simplex/index.html#protocol-description
[2]: https://docs.rs/commonware-consensus/0.0.63/commonware_consensus/simplex/index.html#signing_schemebls12381_threshold
[3]: https://docs.rs/commonware-p2p/0.0.63/commonware_p2p/authenticated/lookup/index.html

## Genesis data

At genesis, `epoch_length` is read from `genesis.config.extra_fields`. The epoch
length should not be changed during the lifetime of the chain (i.e. never).
The initial public polynomial is read from `genesis.extra_data`. And the set of
validators is read from the `ValidatorConfig` smart contract using the
`getValidators` call. The data written to `extra_fields` is a JSON object of
the `{epochLength: <NUMBER>}`, see `TempoGenesisInfo` in [4] for the underlying
Rust struct. The `extra_data` field contains a binary encoding of a triple
`{epoch: <NUMBER>, participants: [<ed25519 pubkey>], public: <bytes>}` using
the commonware codec, see `PublicOutcome` in [5]. And for the validator config
see [6].

[4]: ../crates/chainspec/src/spec.rs
[5]: ../crates/dkg-onchain-artifacts/src/lib.rs
[6]: ../crates/contracts/src/precompiles/validator_config.rs

## Protocol of a DKG ceremony

The process of initializing, running, and completing a DKG ceremony is closely
coupled to finalized blocks. The steps that Tempo is taking to run such a DKG
protocol are this explained in terms of finalized blocks below. One strong
assumption: each finalized block will be processed in strict sequential order.

The *dealers* of the DKG ceremony are the validators of the current/outgoing
epoch. Dealers are each generating a public polynomial and a set of private key
shares for that polynomial, one for each player. The combination of all public
polynomials and private key shares will form a group polynomial with matching
shares. On success, these will become the threshold keys of the new epoch.
The *players* of the DKG ceremony are the validators stored in the smart
contract onchain. On success, they will become the validators of the next epoch.

For a lower level overview of DKG ceremony and the role of players and dealers,
see [7]

The steps below are for starting and performing DKG ceremony of epoch `C`. The
ceremony is initialized with the outcome of the ceremony of epoch `C-1`. Upon
completion, the next epoch `C+1` can be entered using the ceremony outcome of
epoch `C`.

For each finalized block, the actions below will be taken depending on its
height `H`:

1. on `H == C*E-1` (last height of the previous epoch):
   a. read the ceremony players for the *next* epoch `C+1` using the
      `ValidatorConfig::getValidators` call. We call these "syncers". They will
      not be participating in the DKG ceremony `C`, but instead will have time
      to catch up to the network and finally become players during epoch `C+1`.
   b. initialize the DKG ceremony with:
      1. `dealers`: participants as determined by the DKG ceremony run in the
          previous epoch `C-1`.
      2. `players`: syncers as determined by the
         `ValidatorConfig::getValidators` call when setting up the ceremony
         for the previous epoch `C-1`.
      3. `previous_polynomial`: the public polynomial as determined by the DKG
         ceremony of epoch `C-1`.
   c. if a dealer: generate public polynomial and n private key shares (one
      per player).
   d. register p2p peers as the union of `(dealers + players + syncers)` for
      epoch `C` so that the syncers can catch up to the network.
2. on `C*E <= H < (C+1/2)*E` (first half of the epoch):
   a. if a dealer: send a key share to each player in the ceremony.
   b. if a dealer: receive the acknowledgments (`acks`) from each player that
      they have received a key share.
   c. if a player: receive a key share from each dealer, construct and sign
      and `ack` message, and return it to the respective dealer.
3. on `H = (C+1/2)*E` (exact middle of the epoch):
   a. if a dealer: construct the *dealing* or intermediate outcome of the
      ceremony.
4. on `(C+1/2)*E < H <= B-1` (second half of the epoch up to one before boundary):
   a. if a dealer: once the dealer is a proposer, write the dealing/intermediate
      outcome to the `extra_data` field of the block header.
   b: dealer or player: read and store the dealings of the dealers from the
     `extra_data` field.
5. on `H = B-1` (one before the boundary block):
  a. dealer or player: finalize the ceremony, determine its overall outcome
     in the from of a group polynomial (a combination of all polynomials
     generated by the dealers).
  b. on success: store the new polynomial, private key share (if a player), and
     participants in the next ceremony.
  c. on failure: keep the old polynomial, private key share (if a dealer), and
     participants of the old ceremony.
6. on `H = (C+1)*E - 1` (the boundary block):
   a. if a dealer && proposer: write the overall outcome of the DKG ceremony to
      the `extra_data` field of the block header.
   b. if a dealer && verifier: verify that the overall outcome in the
      `extra_data` matches.
   c. dealer or player: enter epoch `C+1` with the outcome of the ceremony in
      epoch `C`.

[7]: https://docs.rs/commonware-cryptography/0.0.63/commonware_cryptography/bls12381/dkg/index.html
   
### On determining ceremony players on the boundary block

Because a finalized block is forwarded to the execution layer and to the DKG
manager (the actor responsible for managing DKG ceremonies) at the same time,
there is no guarantee that the block is executed on the execution layer before
the DKG manager makes the `getValidators` call. However, it is guaranteed that
processing of block `B-1` happened before `B` was forwarded. Thus, when
initializing the DKG ceremony, the DKG manager is reading the state of `B-1` (or
in this, on the first height `C*E` of the current epoch `C`, the boundary block
`C*E-1` of the previous epoch `C-1` will be read).

## Adding a validator to the network

A validator is added to the network using the `ValidatorConfig::addValidator`
contract call, see also [6]. The values written to this contract are read on
the first block of each epoch, as described in the protocol.
