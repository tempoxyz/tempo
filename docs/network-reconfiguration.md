# Network reconfiguration

This spec defines how tempo performs network reconfiguration. Network
reconfiguration is any one of the following cases:

1. a validator is added to the network;
2. a validator is removed from the network;
3. a validator rotates its signing key
   (effectively an atomic validator remove + add);
4. the network reshares its BLS12-381 key.

Network reconfiguration means a network transitions to a new *epoch*.
An *epoch* of a network is defined as the set of validators identified by
their ED25519 public key and a BLS12-381 public key with the shares of the
corresponding private key disstributed among validators.

A change to the validator set requires a resharing of the BLS12-381 set of keys.
It is further advisable to regularly and proactively reshare the BLS12-381 keys.

# Implementation plan

Since every change of the validator set requires a resharing of the BLS12-381
key set, network reconfiguration should first solve resharing and then provide
ways to add/remove validators:

1. make the system epoch aware.
2. implement on-chain BLS12-381 resharing.
3. add validator addition and removal.

## Making the system epoch ware, implementing epochs

In [1] Commonware made its threshold simplex consensus epoch aware. They have
an example for an `Epocher` in-flight [2].

There are 3 major changes that need to be made to make the system epoch aware:

1. define (at genesis) the number of heights H that will make up an epoch.
Epoch 0 will then be heights 1 to H, epoch 1 `H+1` to `2H` (inclusive), epoch 2
will be `2H+1` to `3H` and so on. This is done so the parent block of an epoch
is always the last height of the previous epoch.
2. introduce an `orchestrator` actor responsible for entering new and exiting
old epochs. This actor will now be responsible for spawning consensus engines
per epoch.
3. make the execution driver (the actor implementing the `Automaton` trait
to serve requests from the consensus engine) aware of its epoch.

### The orchestrator

The orchestrator spawns per-epoch consensus engines and listen to
`epoch-transition` events (from the application). Upon a receiving an
epoch-transition event containing a new epoch, the orchestrator will start
a new consensus engiene for that epoch.

### The execution driver

The execution driver must be epoch aware and only serve requests (from the
consensus engine) for its epoch:

1. genesis is always the last height of the previous epoch (so for epoch 0
genesis is height 0, for epoch 1 genesis is H, for nd so on).
2. when requested to propose on top of the last height in its epoch, the
parent digest will be reshared.
3. at the epoch boundary, the execution driver *must not update* the execution
layer (no forkchoice-updates, no new-payload).
4. verification will only permit blocks within its defined epoch (reshared
blocks at the epoch boundary are accepted).
5. when receiving a finalization at the epoch boundary, a `epoch-transition`
event is emitted to the orchestrator.

Resharing the last proposed block at the epoch boundary is critical: the
state machine itself will not make progress, but new notarizations will be
generated (even if the proposals are the same).
This ensures that other validators can indirectly finalize older blocks even
if they didn't receive direct finalizations. This will allow them to transition
to a new epoch.

[1]: https://github.com/commonwarexyz/monorepo/pull/1397
[2]: https://github.com/commonwarexyz/monorepo/pull/1460

## BLS12-381 resharing

Commonware has an example for BLS12-381 resharing using a trusted arbiter [3].
See also [4] for an explanation on the arbiter and how it fits into distributed
key generation and resharing. As explained in [4], for production systems each
validator should run their own arbiter, and resharing should be done over a
replicated log. Commonware are implementing this in a an in-flight PR [5].

*TODO:* how to do the initial DKG at genesis? Hardcode and write to genesis?
Provide a tool to participate in DKG and then write everything to genesis?

[3]: https://github.com/commonwarexyz/monorepo/tree/27333b9762e33462e16e4d1779b1c9267b98cec7/examples/vrf
[4]: https://docs.rs/commonware-cryptography/0.0.62/commonware_cryptography/bls12381/dkg/index.html
[5]: https://github.com/commonwarexyz/monorepo/pull/1796

### Implementing on-chain DKG resharing

In a DKG there are dealers (these will the validators in the outgoing epoch),
and players (the validators of the upcoming epoch). For the purpose of this
implementation step, validators == dealers == players (no changes to the
validator set).

1. define a new p2p channel over which dkg will run.
2. define a "normal operation" epoch `E` and a "reshare" epoch `R` during which
a dkg takes places. Normal operation epochs are all `epoch % 2 == 0` and reshare
epochs are `epoch %2 == 1`.
3. define the number of heights `K` that make up a reshare epoch.
4. write `K` to genesis.
5. at the end of a normal epoch `E`, each validator transitions to the
reshare epoch `R = E + 1` and starts their dkg process.
6. during the first half of of `R`, distribute shares to the other players.
7. at the midpoint of `R`, construct the deal outcome.
8. during the second half of `R`, process deal outcomes by other dealers.
9. at the end of the `R`, finalize the dkg outcome and retrieve the new public
threshold key and get the invidivual share of the private key.
10. transition to the next normal operation epoch `E' = R+1 = E+2`.

### The DKG reshare process

Each DKG process consists of the following steps; each dealer:

1. creates a commitment (public key or polynomial) and a set of private key
shares (the length of the public polynomial and number of shares is defined by
the number of players).
2. in the first half of the reshare epoch `R`:
   1. sends the the tuple `(commitment, shares[i])` to the i-th player.
   2. receives acknowledgements from each player for the tuple. An
   acknowledgement itself is a tuple `((commmitment, share), signature)`, with
   the `signature` over some binary representation of `(commitment, share)`.
   3. receives `(commitment, share)` tuples from other dealers.
   4. sends acknowledgments of the tuple to other dealers.
3. at the midpoint of epoch `R` (at `height % K == K / 2`), construct the deal
outcome - a tuple `outcome := (commitment, acks, reveals)`, where
`acks := [ack]` the acknowledgements received by all players, and
`reaveals := [share]` the shares for which no acknowledgement was received.
4. write `outcome` to a block.
5. read and process the `outcome`s of all other dealers from blocks.
6. at the end of epoch `R`, finalize all outcomes and recover the new group
public polynomial and individual private share.

### Writing and reading blocks

**UNCLEAR**: this section is as of now unclear to me. We need a mechanism:

1. for each validator to write its dkg outcome to a smart contract.
2. to have this information be included in a block (assume an honest proposer
collects all other validators' outcomes and includes them in a block).
3. for each validator to read all other validators' dkg outcomes from blocks.

It is important that a dealer can identify another dealer by its public ed25519
key. This probably means one of 2 things:

1. there is either a mapping of ed25519 -> eth haddress
2. or, a dealer signs its outcome and stores `(outcome, signature)` on the
blockchain so that it can be verified.

### Implementation details

It looks like all dealers and player should be sorted by their public keys. A
lot of commonware operations use player indexes to map players to their
acknowledgments and shares. It's unclear right now if this ordering needs
to be retained across dealers (and players?) or only within a dealer.


## Validator addition and removal

**TODO**
