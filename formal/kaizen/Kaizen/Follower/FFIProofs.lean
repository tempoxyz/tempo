/-
Kaizen follower: the exported FFI step is the verified implementation step instantiated with the
extern oracles, so all refinement and spec theorems apply to kz_step.
-/
import Kaizen.FFI
import Kaizen.Follower.Refinement
import Kaizen.Follower.SpecProofs

namespace Kaizen.FFI

open Kaizen.Follower

/-- kz_step refines the abstract follower step (with verify := kzVerify and
verifyExec := kzVerifyExec). -/
theorem kzStep_refines (s : ImplState) (height : UInt64)
    (blockDigest parentDigest stateRoot cert : ByteArray) (hasDkg : UInt8) (dkgEpoch : UInt64)
    (dkgKey : ByteArray) :
    let c := mkCandidate height blockDigest parentDigest stateRoot cert hasDkg dkgEpoch dkgKey
    (kzStep s height blockDigest parentDigest stateRoot cert hasDkg dkgEpoch dkgKey).code =
        (step kzVerify kzVerifyExec s.abs c.abs).1 ∧
    (kzStep s height blockDigest parentDigest stateRoot cert hasDkg dkgEpoch dkgKey).state.abs =
        (step kzVerify kzVerifyExec s.abs c.abs).2 :=
  implStep_refines kzVerify kzVerifyExec s _

theorem kzNew_abs (L f : UInt64) (k : ByteArray) :
    (kzNew L f k).abs = State.init L.toNat f.toNat k :=
  init_refines L f k

/-- kz_tip_state_root returns the abstract tip's state root. -/
theorem kzTipStateRoot_abs (s : ImplState) (t : Tip) (h : s.abs.tip = some t) :
    kzTipStateRoot s = t.stateRoot := by
  unfold kzTipStateRoot
  cases ht : s.tip with
  | none => simp [ImplState.abs, ht] at h
  | some it =>
    simp only [ImplState.abs, ht, Option.map_some, Option.some.injEq] at h
    rw [← h]; rfl

/-- End-to-end: any sequence of kz_step calls from kz_new, on arbitrary inputs, only ever has a
Finalized tip, provided the assumptions hold for the extern oracles. -/
theorem kz_run_tip_finalized {Finalized : Nat → ByteArray → ByteArray → Prop}
    {Committed : Candidate → Prop} {Executed : ByteArray → ByteArray → ByteArray → Prop}
    {Sound : Nat → ByteArray → Prop} (L f : UInt64) (k : ByteArray)
    (A : Assumptions kzVerify kzVerifyExec Finalized Committed Executed Sound L.toNat f.toNat k)
    (cs : List ImplCandidate) (hcs : AllCommitted Committed (cs.map ImplCandidate.abs))
    {t : Tip} (ht : ((implRun kzVerify kzVerifyExec (kzNew L f k) cs).1.abs).tip = some t) :
    ∃ p, Finalized t.height t.digest p := by
  rw [(implRun_refines kzVerify kzVerifyExec cs (kzNew L f k)).1, kzNew_abs] at ht
  exact run_tip_finalized A _ hcs ht

/-- End-to-end execution: the blocks accepted by a sequence of kz_step calls from kz_new form a
valid execution chain from the anchor (first accepted block's state root). -/
theorem kz_run_executed {Finalized : Nat → ByteArray → ByteArray → Prop}
    {Committed : Candidate → Prop} {Executed : ByteArray → ByteArray → ByteArray → Prop}
    {Sound : Nat → ByteArray → Prop} (L f : UInt64) (k : ByteArray)
    (A : Assumptions kzVerify kzVerifyExec Finalized Committed Executed Sound L.toNat f.toNat k)
    (cs : List ImplCandidate) (hcs : AllCommitted Committed (cs.map ImplCandidate.abs)) :
    let acc := (implRun kzVerify kzVerifyExec (kzNew L f k) cs).2.map ImplCandidate.abs
    ∀ (i : Nat) (h : i + 1 < acc.length),
      Executed acc[i].stateRoot acc[i + 1].blockDigest acc[i + 1].stateRoot := by
  have gen : ∀ l : List Candidate, l = (run kzVerify kzVerifyExec (State.init L.toNat f.toNat k)
      (cs.map ImplCandidate.abs)).2 → ∀ (i : Nat) (h : i + 1 < l.length),
      Executed l[i].stateRoot l[i + 1].blockDigest l[i + 1].stateRoot := by
    rintro l rfl; exact run_executed A _ hcs
  exact gen _ (by rw [(implRun_refines kzVerify kzVerifyExec cs (kzNew L f k)).2, kzNew_abs])

/-- The tip after a sequence of kz_step calls from kz_new is a committed input candidate whose
digest and state root it records. -/
theorem kz_run_tip_last {Committed : Candidate → Prop} (L f : UInt64) (k : ByteArray)
    (cs : List ImplCandidate) (hcs : AllCommitted Committed (cs.map ImplCandidate.abs))
    {t : Tip} (ht : ((implRun kzVerify kzVerifyExec (kzNew L f k) cs).1.abs).tip = some t) :
    ∃ c, Committed c ∧ t.height = c.height ∧ t.digest = c.blockDigest ∧
      t.stateRoot = c.stateRoot := by
  rw [(implRun_refines kzVerify kzVerifyExec cs (kzNew L f k)).1, kzNew_abs] at ht
  obtain ⟨c, hc, h1, h2, h3⟩ := run_tip_state_root kzVerify kzVerifyExec _ _ _ _ ht
  have hmem := run_accepted_mem kzVerify kzVerifyExec _ _ c (List.mem_of_getLast? hc)
  exact ⟨c, hcs c hmem, h1, h2, h3⟩

end Kaizen.FFI
