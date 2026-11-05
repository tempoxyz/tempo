/-
Kaizen follower: Stage II executable implementation (Mathlib-free; Init + Std only).
-/
import Std.Data.HashMap
import Kaizen.Follower.Spec

namespace Kaizen.Follower

/-- Executable tip. -/
structure ImplTip where
  height : UInt64
  digest : ByteArray
  epoch : UInt64
  view : UInt64

/-- Executable follower state. -/
structure ImplState where
  tip : Option ImplTip
  epochLength : UInt64
  fromEpoch : UInt64
  networkKey : ByteArray
  learned : Std.HashMap UInt64 ByteArray

/-- Executable step input. -/
structure ImplCandidate where
  height : UInt64
  blockDigest : ByteArray
  parentDigest : ByteArray
  cert : ByteArray
  dkg : Option (UInt64 × ByteArray)

def ImplState.init (epochLength fromEpoch : UInt64) (networkKey : ByteArray) : ImplState :=
  ⟨none, epochLength, fromEpoch, networkKey, {}⟩

def ImplState.identity (s : ImplState) (e : UInt64) : Option ByteArray :=
  match s.learned[e]? with
  | some k => some k
  | none => if s.fromEpoch ≤ e then some s.networkKey else none

def implTipCheck (tip : Option ImplTip) (c : ImplCandidate) (fc : Cert) : Option UInt8 :=
  match tip with
  | none => none
  | some t =>
    if ¬ (c.height ≠ 0 ∧ c.height - 1 = t.height) then some Code.heightNotNext
    else if c.parentDigest ≠ t.digest then some Code.parentMismatch
    else if ¬ (t.epoch < fc.epoch ∨ (t.epoch = fc.epoch ∧ t.view < fc.view)) then
      some Code.roundNotIncreasing
    else none

def implDkgCheck (L : UInt64) (learned : Std.HashMap UInt64 ByteArray) (c : ImplCandidate)
    (fc : Cert) : Except UInt8 (Std.HashMap UInt64 ByteArray) :=
  if c.height % L = L - 1 then
    match c.dkg with
    | none => .error Code.missingDkg
    | some (e', k) =>
      if ¬ (e' ≠ 0 ∧ e' - 1 = fc.epoch) then .error Code.dkgEpochMismatch
      else .ok (learned.insert e' k)
  else .ok learned

/-- The executable follower step. -/
def implStep (verify : Verify) (s : ImplState) (c : ImplCandidate) : UInt8 × ImplState :=
  if s.epochLength = 0 then (Code.badConfig, s) else
  match decodeCert c.cert with
  | none => (Code.malformed, s)
  | some fc =>
    if fc.payload ≠ c.blockDigest then (Code.digestMismatch, s) else
    if fc.epoch ≠ c.height / s.epochLength then (Code.epochMismatch, s) else
    match implTipCheck s.tip c fc with
    | some code => (code, s)
    | none =>
      match implDkgCheck s.epochLength s.learned c fc with
      | .error code => (code, s)
      | .ok learned' =>
        match s.identity fc.epoch with
        | none => (Code.identityUnavailable, s)
        | some key =>
          if verify key fc.epoch fc.view fc.parent fc.payload fc.sig = false then
            (Code.badSignature, s)
          else (Code.accepted,
            { s with tip := some ⟨c.height, c.blockDigest, fc.epoch, fc.view⟩, learned := learned' })

/-! ## Abstraction functions -/

def ImplTip.abs (t : ImplTip) : Tip := ⟨t.height.toNat, t.digest, t.epoch.toNat, t.view.toNat⟩

def absLearned (m : Std.HashMap UInt64 ByteArray) (e : Nat) : Option ByteArray :=
  if e < 2 ^ 64 then m[e.toUInt64]? else none

def ImplState.abs (s : ImplState) : State :=
  ⟨s.tip.map ImplTip.abs, s.epochLength.toNat, s.fromEpoch.toNat, s.networkKey,
    absLearned s.learned⟩

def ImplCandidate.abs (c : ImplCandidate) : Candidate :=
  ⟨c.height.toNat, c.blockDigest, c.parentDigest, c.cert, c.dkg.map (fun p => (p.1.toNat, p.2))⟩

end Kaizen.Follower
