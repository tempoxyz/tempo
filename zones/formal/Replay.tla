------------------------------ MODULE Replay -----------------------------
EXTENDS Zones, Observations

VARIABLE cursor
replayVars == <<s, cursor>>

(* Only measured fields are compared. Unobserved cross-chain components are
   fixture inputs, not claimed to have executed in the source process. *)
Snapshot(r) == [funded |-> r.funded, escrow |-> r.escrow, supply |-> r.supply,
    released |-> r.released, portalRefund |-> r.portalRefund,
    zoneRefund |-> r.zoneRefund, depositCount |-> Len(r.deposits),
    processed |-> r.processed, acceptedCursor |-> r.acceptedCursor,
    pendingCount |-> Len(r.pending), finalized |-> r.finalized,
    acceptedBatches |-> r.acceptedBatches, head |-> r.head, tail |-> r.tail,
    nextNonce |-> r.nextNonce, fallbackCount |-> Cardinality(r.fallback)]
Matches(r, observation) ==
    \A key \in DOMAIN observation : Snapshot(r)[key] = observation[key]

Step(action) == CASE action = "fund" -> Fund
    [] action = "advance_ok" -> AdvanceWith([i \in 1..Len(Remaining(s)) |-> TRUE])
    [] action = "advance_fail" -> AdvanceWith([i \in 1..Len(Remaining(s)) |-> FALSE])
    [] action = "request" -> Request
    [] action = "finalize" -> Finalize
    [] action = "submit" -> Submit
    [] action = "deliver_ok" -> Deliver(TRUE)
    [] action = "deliver_fail" -> Deliver(FALSE)
    [] action = "claim_portal" -> ClaimPortal
    [] action = "claim_zone" -> ClaimZone
    [] action = "retry" -> UNCHANGED s
    [] action = "complete" -> UNCHANGED s
    [] OTHER -> FALSE

ReplayInit == /\ Init /\ cursor = 1 /\ Trace[1].action = "init"
              /\ Matches(s, Trace[1].state)
ReplayNext ==
    \/ /\ cursor < Len(Trace)
       /\ Step(Trace[cursor + 1].action)
       /\ Matches(s', Trace[cursor + 1].state)
       /\ cursor' = cursor + 1
    \/ /\ cursor = Len(Trace) /\ UNCHANGED replayVars

(* Each recorded action fixes its nondeterministic outcome, so the replay has
   at most one successor. A mismatch deadlocks before the terminal self-loop. *)
ReplaySpec == ReplayInit /\ [][ReplayNext]_replayVars
=============================================================================
