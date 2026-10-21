------------------------------ MODULE Zones ------------------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS MaxDeposits, MaxWithdrawals, MaxBatches, Capacity, Reserve
ASSUME /\ MaxDeposits > 0 /\ MaxWithdrawals > 0 /\ MaxBatches > 0
       /\ Capacity > Reserve /\ Reserve > 0

VARIABLE s
vars == <<s>>

Withdrawal(kind, nonce) == [kind |-> kind, nonce |-> nonce]
Deposit(kind, nonce) == [kind |-> kind, nonce |-> nonce]
Items(q) == UNION { {q[i][j] : j \in 1..Len(q[i])} : i \in 1..Len(q) }
RECURSIVE ItemCount(_)
ItemCount(q) == IF q = <<>> THEN 0 ELSE Len(Head(q)) + ItemCount(Tail(q))
SealedItems(q) == [i \in 1..Len(q) |-> q[i].items]
Remaining(r) == SubSeq(r.deposits, r.processed + 1, Len(r.deposits))
UserDeposits(r) == Cardinality({i \in 1..Len(Remaining(r)) :
                               Remaining(r)[i].kind = "user"})
BounceDeposits(r) == Cardinality({i \in 1..Len(Remaining(r)) :
                                 Remaining(r)[i].kind = "bounce"})

Init == s = [funded |-> 0, escrow |-> 0, supply |-> 0, released |-> 0,
             portalRefund |-> 0, zoneRefund |-> 0,
             deposits |-> <<>>, processed |-> 0, acceptedCursor |-> 0,
             pending |-> <<>>, sealed |-> <<>>, portal |-> <<>>,
             finalized |-> 0, acceptedBatches |-> 0,
             head |-> 0, tail |-> 0, nextNonce |-> 0, fallback |-> {}]

(* Spec: Deposits / Deposit Queue. Fees are zero; one unit per operation. *)
Fund == /\ s.funded < MaxDeposits
        /\ Len(s.deposits) - s.acceptedCursor < Capacity - Reserve
        /\ s' = [s EXCEPT !.funded = @ + 1, !.escrow = @ + 1,
                    !.deposits = Append(@, Deposit("user", 0))]

ImportOne(r, d, ok) ==
    IF d.kind = "user"
    THEN IF ok THEN [r EXCEPT !.supply = @ + 1]
         ELSE [r EXCEPT !.pending = Append(@, Withdrawal("refund", 0))]
    ELSE IF ok THEN [r EXCEPT !.supply = @ + 1,
                             !.fallback = @ \ {d.nonce}]
         ELSE [r EXCEPT !.zoneRefund = @ + 1,
                        !.fallback = @ \ {d.nonce}]

RECURSIVE ImportAll(_, _, _, _)
ImportAll(r, ds, outcomes, i) ==
    IF i > Len(ds) THEN r
    ELSE ImportAll(ImportOne(r, ds[i], outcomes[i]), ds, outcomes, i + 1)

(* One atomic advanceTempo imports the entire anchored queue suffix. *)
AdvanceWith(outcomes) ==
    /\ s.processed < Len(s.deposits)
    /\ s' = [ImportAll(s, Remaining(s), outcomes, 1)
             EXCEPT !.processed = Len(s.deposits)]
Advance == \E outcomes \in [1..Len(Remaining(s)) -> BOOLEAN] : AdvanceWith(outcomes)

(* Spec: Withdrawal Request. Nonces remain mapped until bounce-back import. *)
Request == /\ s.supply > 0 /\ s.nextNonce < MaxWithdrawals
           /\ s' = [s EXCEPT !.supply = @ - 1,
                       !.pending = Append(@, Withdrawal("user", s.nextNonce + 1)),
                       !.nextNonce = @ + 1,
                       !.fallback = @ \cup {s.nextNonce + 1}]

(* Finalized on the zone is distinct from accepted on Tempo, even if empty. *)
Finalize == /\ s.finalized < MaxBatches
            /\ s' = [s EXCEPT !.sealed = Append(@,
                                 [cursor |-> s.processed, items |-> s.pending]),
                        !.pending = <<>>, !.finalized = @ + 1]

Submit == /\ s.sealed # <<>>
          /\ LET batch == Head(s.sealed)
             IN /\ batch.cursor >= s.acceptedCursor
                /\ s' = [s EXCEPT !.sealed = Tail(@),
                            !.acceptedCursor = batch.cursor,
                            !.acceptedBatches = @ + 1,
                            !.portal = IF batch.items = <<>> THEN @
                                       ELSE Append(@, batch.items),
                            !.tail = IF batch.items = <<>> THEN @ ELSE @ + 1]

(* Spec: Withdrawal Processing / Failures. A one-item FIFO prefix is sufficient
   to model splitting a batch. Callback success is abstracted as delivery to L1;
   a callback's re-deposit is a separate Fund action, outside this pilot. *)
Deliver(ok) ==
    /\ s.portal # <<>>
    /\ Len(s.deposits) - s.acceptedCursor < Capacity
    /\ LET batch == Head(s.portal)
           w == Head(batch)
           queues == IF Len(batch) = 1 THEN Tail(s.portal)
                     ELSE <<Tail(batch)>> \o Tail(s.portal)
           dequeued == [s EXCEPT !.portal = queues,
                                !.head = IF Len(batch) = 1 THEN @ + 1 ELSE @]
       IN s' = IF ok
               THEN [dequeued EXCEPT !.escrow = @ - 1, !.released = @ + 1]
               ELSE IF w.kind = "refund"
                    THEN [dequeued EXCEPT !.portalRefund = @ + 1]
                    ELSE [dequeued EXCEPT
                          !.deposits = Append(@, Deposit("bounce", w.nonce))]

ClaimPortal == /\ s.portalRefund > 0
               /\ s' = [s EXCEPT !.portalRefund = @ - 1,
                           !.escrow = @ - 1, !.released = @ + 1]
ClaimZone == /\ s.zoneRefund > 0
             /\ s' = [s EXCEPT !.zoneRefund = @ - 1, !.supply = @ + 1]

(* Reverted calls and retries after an already accepted operation stutter. *)
Next == Fund \/ Advance \/ Request \/ Finalize \/ Submit
        \/ Deliver(TRUE) \/ Deliver(FALSE) \/ ClaimPortal \/ ClaimZone
Spec == Init /\ [][Next]_vars

TypeOK == /\ s.funded \in 0..MaxDeposits
          /\ s.nextNonce \in 0..MaxWithdrawals
          /\ s.finalized \in 0..MaxBatches
          /\ s.escrow \in Nat /\ s.supply \in Nat /\ s.released \in Nat
          /\ s.portalRefund \in Nat /\ s.zoneRefund \in Nat
          /\ s.fallback \subseteq 1..MaxWithdrawals
          /\ s.acceptedBatches \in 0..s.finalized
          /\ s.acceptedCursor \in 0..s.processed
          /\ s.processed \in 0..Len(s.deposits)
          /\ s.head \in 0..s.tail
          /\ \A d \in {s.deposits[i] : i \in 1..Len(s.deposits)} :
                 /\ d.kind \in {"user", "bounce"}
                 /\ d.nonce \in 0..MaxWithdrawals
          /\ \A w \in ({s.pending[i] : i \in 1..Len(s.pending)}
                       \cup Items(SealedItems(s.sealed)) \cup Items(s.portal)) :
                 /\ w.kind \in {"user", "refund"}
                 /\ w.nonce \in 0..MaxWithdrawals
Conservation == s.funded = s.released + s.supply + s.zoneRefund
                 + s.portalRefund + UserDeposits(s) + BounceDeposits(s)
                 + Len(s.pending) + ItemCount(SealedItems(s.sealed))
                 + ItemCount(s.portal)
EscrowBacking == /\ s.escrow = s.funded - s.released
                 /\ s.escrow >= s.supply + s.zoneRefund + s.portalRefund
DepositCapacity == Len(s.deposits) - s.acceptedCursor <= Capacity
QueueIndices == s.head + Len(s.portal) = s.tail

(* Successful L1 delivery does NOT consume the zone-local fallback mapping.
   It is intentionally retained by the implementation; no cross-chain delete
   exists. The model only requires every unimported bounce-back to be mapped. *)
FallbackAvailable == \A i \in 1..Len(Remaining(s)) :
    Remaining(s)[i].kind = "bounce" => Remaining(s)[i].nonce \in s.fallback
=============================================================================
