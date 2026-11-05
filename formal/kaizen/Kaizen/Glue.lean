import Kaizen.Simplex.All
import Kaizen.Follower.FFIProofs

/-!
Kaizen.Glue: connect Stage I (Simplex safety, one instance per epoch) to the follower's
H_unique hypothesis, and state the end-to-end agreement theorem for the extracted core.

A Tempo chain is modelled as one Simplex instance per epoch. Epoch 'e' runs with its own
validator configuration and reaches some reachable state; its proposals' payloads are block
digests, and a proposal at instance-local height 'k' sits at global height 'base e + k'.
Only proposals at heights inside epoch 'e''s range ('h / L = e', Tempo's FixedEpocher)
count as finalized blocks of the chain, which is also what the follower checks.
-/

namespace Kaizen.Glue

open Kaizen.Simplex Kaizen.Follower

/-- The payload (block digest) of a non-genesis proposal. -/
def payload? : Block ByteArray → Option ByteArray
  | .genesis => none
  | .mk _ x _ => some x

/-- A Tempo chain: one reachable Simplex instance per epoch. -/
structure Epochs (L : Nat) where
  cfg : Nat → Config
  st : (e : Nat) → State (cfg e).n ByteArray
  reach : ∀ e, Reachable (cfg e) (st e)
  /-- Global height of epoch 'e''s instance genesis (the previous epoch's boundary block). -/
  base : Nat → Nat

/-- Block digest 'd' is finalized at global height 'h'. -/
def Finalized {L : Nat} (E : Epochs L) (h : Nat) (d _parent : ByteArray) : Prop :=
  ∃ e b, finalized (E.cfg e) (E.st e) b ∧ payload? b = some d ∧ E.base e + b.height = h ∧ h / L = e

/-- H_unique, discharged from 'Kaizen.Simplex.finalized_unique_at_height'. -/
theorem unique {L : Nat} (E : Epochs L) : UniqueFinalized (Finalized E) := by
  intro h d1 p1 d2 p2 ⟨e1, b1, f1, x1, h1, r1⟩ ⟨e2, b2, f2, x2, h2, r2⟩
  have he : e1 = e2 := r1.symm.trans r2
  subst he
  have hb : b1 = b2 := finalized_unique_at_height (E.reach e1) f1 f2 (by omega)
  subst hb
  rw [x1] at x2
  exact Option.some.inj x2

/-- End to end: two runs of the extracted follower core (the exact code the Rust shim links),
started from the same configuration and fed arbitrary, possibly adversarial, candidate
sequences, never accept different block digests at the same height, provided the shim's
obligations hold (Assumptions: BLS soundness, sound network identity, sound DKG outcomes in
finalized boundary blocks; AllCommitted: candidate fields are bound to the hashed header). -/
theorem extracted_followers_agree {L : Nat} (E : Epochs L) {Committed : Candidate → Prop}
    {Sound : Nat → ByteArray → Prop} (l f : UInt64) (k : ByteArray)
    (A : Assumptions Kaizen.FFI.kzVerify (Finalized E) Committed Sound l.toNat f.toNat k)
    (xs1 xs2 : List ImplCandidate)
    (C1 : AllCommitted Committed (xs1.map ImplCandidate.abs))
    (C2 : AllCommitted Committed (xs2.map ImplCandidate.abs)) :
    ∀ t1 t2,
      ((implRun Kaizen.FFI.kzVerify (Kaizen.FFI.kzNew l f k) xs1).1.abs).tip = some t1 →
      ((implRun Kaizen.FFI.kzVerify (Kaizen.FFI.kzNew l f k) xs2).1.abs).tip = some t2 →
      t1.height = t2.height → t1.digest = t2.digest := by
  intro t1 t2 h1 h2 hh
  obtain ⟨p1, f1⟩ := Kaizen.FFI.kz_run_tip_finalized l f k A xs1 C1 h1
  obtain ⟨p2, f2⟩ := Kaizen.FFI.kz_run_tip_finalized l f k A xs2 C2 h2
  exact unique E _ _ _ _ _ f1 (hh ▸ f2)

end Kaizen.Glue
