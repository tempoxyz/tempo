/-
Kaizen follower: Stage I abstract follower specification (Mathlib-free).

Mirrors Tempo's FinalizationVerifier::decode_and_verify / verify_certificate and the follow
driver's sequential acceptance of finalized blocks.
-/
import Kaizen.Follower.Codec

namespace Kaizen.Follower

/-- The signature oracle: verify key epoch view parentView payload certBytes.
In Kaizen.FFI it is the extern kz_verify_finalization; everywhere else it is a parameter. -/
abbrev Verify := ByteArray → UInt64 → UInt64 → UInt64 → ByteArray → ByteArray → Bool

/-! Result codes. -/
namespace Code
def accepted : UInt8 := 0
def malformed : UInt8 := 1
def digestMismatch : UInt8 := 2
def epochMismatch : UInt8 := 3
def identityUnavailable : UInt8 := 4
def badSignature : UInt8 := 5
def heightNotNext : UInt8 := 6
def parentMismatch : UInt8 := 7
def roundNotIncreasing : UInt8 := 8
def missingDkg : UInt8 := 9
def dkgEpochMismatch : UInt8 := 10
def badConfig : UInt8 := 11
end Code

/-- Accepted tip: height, digest, round = (epoch, view). -/
structure Tip where
  height : Nat
  digest : ByteArray
  epoch : Nat
  view : Nat
  deriving DecidableEq

/-- Abstract follower state. -/
structure State where
  tip : Option Tip
  epochLength : Nat
  fromEpoch : Nat
  networkKey : ByteArray
  learned : Nat → Option ByteArray

/-- Abstract step input. dkg is the (epoch, identity key) the shim parsed from extra_data. -/
structure Candidate where
  height : Nat
  blockDigest : ByteArray
  parentDigest : ByteArray
  cert : ByteArray
  dkg : Option (Nat × ByteArray)

/-- Initial state (no tip, nothing learned). -/
def State.init (epochLength fromEpoch : Nat) (networkKey : ByteArray) : State :=
  ⟨none, epochLength, fromEpoch, networkKey, fun _ => none⟩

/-- Lexicographic round order. -/
def roundLt (e1 v1 e2 v2 : Nat) : Prop := e1 < e2 ∨ (e1 = e2 ∧ v1 < v2)

instance (e1 v1 e2 v2 : Nat) : Decidable (roundLt e1 v1 e2 v2) := by
  unfold roundLt; infer_instance

/-- Identity used for epoch e: learned entry, else the network identity if e ≥ fromEpoch. -/
def State.identity (s : State) (e : Nat) : Option ByteArray :=
  match s.learned e with
  | some k => some k
  | none => if s.fromEpoch ≤ e then some s.networkKey else none

/-- Linkage to the current tip: none if OK, else a rejection code. -/
def tipCheck (tip : Option Tip) (c : Candidate) (fc : SpecCert) : Option UInt8 :=
  match tip with
  | none => none
  | some t =>
    if c.height ≠ t.height + 1 then some Code.heightNotNext
    else if c.parentDigest ≠ t.digest then some Code.parentMismatch
    else if ¬ roundLt t.epoch t.view fc.epoch fc.view then some Code.roundNotIncreasing
    else none

/-- Boundary handling (FixedEpocher: epoch e covers heights [e*L, (e+1)*L - 1], so a height is
the last of its epoch iff height % L = L - 1). Returns the updated learned map or a code. -/
def dkgCheck (L : Nat) (learned : Nat → Option ByteArray) (c : Candidate) (fc : SpecCert) :
    Except UInt8 (Nat → Option ByteArray) :=
  if c.height % L = L - 1 then
    match c.dkg with
    | none => .error Code.missingDkg
    | some (e', k) =>
      if e' ≠ fc.epoch + 1 then .error Code.dkgEpochMismatch
      else .ok (fun x => if x = e' then some k else learned x)
  else .ok learned

/-- The abstract follower step. On rejection the state is unchanged. -/
def step (verify : Verify) (s : State) (c : Candidate) : UInt8 × State :=
  if s.epochLength = 0 then (Code.badConfig, s) else
  match specDecode c.cert.data.toList with
  | none => (Code.malformed, s)
  | some fc =>
    if fc.payload ≠ c.blockDigest.data.toList then (Code.digestMismatch, s) else
    if fc.epoch ≠ c.height / s.epochLength then (Code.epochMismatch, s) else
    match tipCheck s.tip c fc with
    | some code => (code, s)
    | none =>
      match dkgCheck s.epochLength s.learned c fc with
      | .error code => (code, s)
      | .ok learned' =>
        match s.identity fc.epoch with
        | none => (Code.identityUnavailable, s)
        | some key =>
          if verify key fc.epoch.toUInt64 fc.view.toUInt64 fc.parent.toUInt64
              ⟨fc.payload.toArray⟩ ⟨fc.sig.toArray⟩ = false then (Code.badSignature, s)
          else (Code.accepted,
            { s with tip := some ⟨c.height, c.blockDigest, fc.epoch, fc.view⟩, learned := learned' })

/-- Run a sequence of candidates; returns the final state and the accepted candidates in order. -/
def run (verify : Verify) : State → List Candidate → State × List Candidate
  | s, [] => (s, [])
  | s, c :: cs =>
    let r := step verify s c
    let rest := run verify r.2 cs
    if r.1 = Code.accepted then (rest.1, c :: rest.2) else rest

end Kaizen.Follower
