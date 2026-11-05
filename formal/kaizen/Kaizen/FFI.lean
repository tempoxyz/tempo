/-
Kaizen follower FFI surface (Mathlib-free: imports only Init/Std through Kaizen.Follower.Impl).

The BLS oracle is provided by the Rust shim as the C symbol kz_verify_finalization; every
other module takes verify as a parameter so the theorems apply to this instance.

Ownership: kz_step consumes its ImplState argument (owned, enabling in-place HashMap updates);
the shim must lean_inc it first if it wants to keep the old state. ByteArray arguments of the
all exported functions are owned (consumed; Lean forbids borrow annotations on @[export]):
the shim must lean_inc an object before passing it if it keeps using it, e.g. before calling
kz_out_code and then kz_out_state on the same StepOut. The oracle's @& arguments
(key, payload, sig) are borrowed: the Rust side must not dec them. Returned objects are owned.
-/
import Kaizen.Follower.Impl

namespace Kaizen.FFI

open Kaizen.Follower

/-- BLS12-381 threshold (MinSig) finalization verification, implemented in Rust. -/
@[extern "kz_verify_finalization"]
opaque kzVerify (key : @& ByteArray) (epoch view parent : UInt64) (payload : @& ByteArray)
    (sig : @& ByteArray) : Bool

/-- Result of one step. -/
structure StepOut where
  state : ImplState
  code : UInt8

@[export kz_new]
def kzNew (epochLength : UInt64) (fromEpoch : UInt64) (networkKey : ByteArray) : ImplState :=
  ImplState.init epochLength fromEpoch networkKey

/-- The input candidate assembled from the C arguments. -/
def mkCandidate (height : UInt64) (blockDigest parentDigest cert : ByteArray) (hasDkg : UInt8)
    (dkgEpoch : UInt64) (dkgKey : ByteArray) : ImplCandidate :=
  ⟨height, blockDigest, parentDigest, cert, if hasDkg ≠ 0 then some (dkgEpoch, dkgKey) else none⟩

@[export kz_step]
def kzStep (s : ImplState) (height : UInt64) (blockDigest parentDigest cert : ByteArray)
    (hasDkg : UInt8) (dkgEpoch : UInt64) (dkgKey : ByteArray) : StepOut :=
  let r := implStep kzVerify s (mkCandidate height blockDigest parentDigest cert hasDkg dkgEpoch dkgKey)
  ⟨r.2, r.1⟩

@[export kz_out_state]
def kzOutState (o : StepOut) : ImplState := o.state

@[export kz_out_code]
def kzOutCode (o : StepOut) : UInt8 := o.code

@[export kz_has_tip]
def kzHasTip (s : ImplState) : UInt8 := if s.tip.isSome then 1 else 0

@[export kz_tip_height]
def kzTipHeight (s : ImplState) : UInt64 :=
  match s.tip with
  | some t => t.height
  | none => 0

@[export kz_tip_digest]
def kzTipDigest (s : ImplState) : ByteArray :=
  match s.tip with
  | some t => t.digest
  | none => ByteArray.empty

end Kaizen.FFI
