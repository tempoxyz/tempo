/-
Kaizen follower: the exported FFI step is the verified implementation step instantiated with the
extern oracle, so all refinement and spec theorems apply to kz_step.
-/
import Kaizen.FFI
import Kaizen.Follower.Refinement
import Kaizen.Follower.SpecProofs

namespace Kaizen.FFI

open Kaizen.Follower

/-- kz_step refines the abstract follower step (with verify := kzVerify). -/
theorem kzStep_refines (s : ImplState) (height : UInt64) (blockDigest parentDigest cert : ByteArray)
    (hasDkg : UInt8) (dkgEpoch : UInt64) (dkgKey : ByteArray) :
    let c := mkCandidate height blockDigest parentDigest cert hasDkg dkgEpoch dkgKey
    (kzStep s height blockDigest parentDigest cert hasDkg dkgEpoch dkgKey).code =
        (step kzVerify s.abs c.abs).1 ∧
    (kzStep s height blockDigest parentDigest cert hasDkg dkgEpoch dkgKey).state.abs =
        (step kzVerify s.abs c.abs).2 :=
  implStep_refines kzVerify s _

theorem kzNew_abs (L f : UInt64) (k : ByteArray) :
    (kzNew L f k).abs = State.init L.toNat f.toNat k :=
  init_refines L f k

/-- End-to-end: any sequence of kz_step calls from kz_new, on arbitrary inputs, only ever has a
Finalized tip, provided the assumptions hold for the extern oracle. -/
theorem kz_run_tip_finalized {Finalized : Nat → ByteArray → ByteArray → Prop}
    {Committed : Candidate → Prop} {Sound : Nat → ByteArray → Prop} (L f : UInt64) (k : ByteArray)
    (A : Assumptions kzVerify Finalized Committed Sound L.toNat f.toNat k)
    (cs : List ImplCandidate) (hcs : AllCommitted Committed (cs.map ImplCandidate.abs))
    {t : Tip} (ht : ((implRun kzVerify (kzNew L f k) cs).1.abs).tip = some t) :
    ∃ p, Finalized t.height t.digest p := by
  rw [(implRun_refines kzVerify cs (kzNew L f k)).1, kzNew_abs] at ht
  exact run_tip_finalized A _ hcs ht

end Kaizen.FFI
