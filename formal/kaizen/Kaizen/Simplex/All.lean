import Kaizen.Simplex.Block
import Kaizen.Simplex.Protocol
import Kaizen.Simplex.Safety

/-!
# Kaizen Stage I: Commonware Simplex consensus, abstract protocol and safety

Main results:
* 'Kaizen.Simplex.safety': in every reachable state, two proposals with finalization
  certificates lie on one chain (one extends the other).
* 'Kaizen.Simplex.finalized_unique_at_height': two finalized proposals with equal height
  are equal.
* 'Kaizen.Simplex.finalized_unique_at_view', 'Kaizen.Simplex.finalized_not_nullified':
  per-view consequences used by a follower.

## Model assumptions (trusted computing base of Stage I)

1. Validators are 'Fin n'; the Byzantine set 'byz' has at most 'f' members and is fixed
   for the whole execution (one epoch, static validator set).
2. Quorum 'q' satisfies 'n + f < 2q' (two quorums share more than 'f' validators).
   Commonware's N3f1 quorum 2f+1 = n - f with n = 3f+1 satisfies it ('quorum_n_sub_f').
3. Signatures are unforgeable and certificates are sound: a certificate for a vote exists
   exactly when at least 'q' distinct validators cast that vote ('State.Cert'). For
   threshold BLS this is the assumption that a valid threshold signature implies a
   quorum of partial signatures; it is not proved here.
4. A proposal determines its parent proposal ('Block.mk view payload parent'): the payload
   digest is collision resistant and commits to the parent.
5. Honest voters follow Commonware's voting rules with 'term_length = 1' (no stable
   leaders, no optimistic validation, no pipelined handoff):
   * notarize 'mk v x p' only if 'p.view < v', the parent is genesis or has a notarization
     or finalization certificate (application certification is abstracted as a
     notarization), every view strictly between 'p.view' and 'v' has a nullification
     certificate, and it has not notarized or finalized another proposal at 'v';
   * nullify 'v' only if it has not finalized at 'v';
   * finalize 'b' only if 'b' has a notarization certificate, it has not nullified
     'b.view' and has not notarized a different proposal at 'b.view'.
   Preconditions are read on the global vote set, which over-approximates every honest
   voter's local knowledge, so the model allows more behaviour than Commonware does.
6. Byzantine validators may cast any vote at any time. Network, timing and leader
   election are not modelled: they affect liveness only.
7. Genesis (view 0) is implicitly finalized and has no certificate.
-/
